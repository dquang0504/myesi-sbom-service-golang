package services

import (
	"context"
	"encoding/json"
	"log"
	"myesi-sbom-service-golang/internal/config"
	"time"

	"github.com/segmentio/kafka-go"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
)

// Kafka config
const (
	KafkaTopic = "sbom-events"
)

// SBOMEvent struct is the payload which gets sent to Vulnerability Service
type SBOMEvent struct {
	SBOMID     string              `json:"sbom_id"`
	Project    string              `json:"project_name"`
	Components []map[string]string `json:"components"`
}

// PublishSBOMEvent publishes the event onto Kafka after SBOM creation
func PublishSBOMEvent(sbomID string, project string, comps []map[string]string, operation string) {
	//open telemetry initialization: used for message tracing
	ctx, span := otel.Tracer("sbom-service").Start(context.Background(), "PublishSBOMEvent")
	defer span.End()

	event := SBOMEvent{
		SBOMID:     sbomID,
		Project:    project,
		Components: comps,
	}
	data, err := json.Marshal(event)
	if err != nil {
		log.Println("Kafka: cannot marshal SBOM event: ", err)
		return
	}

	//Inject OTel trace context into Kafka headers
	headers := make([]kafka.Header, 0)
	propagator := otel.GetTextMapPropagator()
	carrier := kafkaHeaderCarrier{&headers}
	propagator.Inject(ctx, carrier)

	writer := kafka.Writer{
		Addr:         kafka.TCP(config.LoadConfig().KafkaBroker),
		Topic:        KafkaTopic,
		Balancer:     &kafka.LeastBytes{},
		RequiredAcks: kafka.RequireAll,
		Async:        false,
	}
	defer writer.Close()

	msg := kafka.Message{
		Key:     []byte(sbomID),
		Value:   data,
		Time:    time.Now(),
		Headers: headers,
	}

	if err = writer.WriteMessages(ctx, msg); err != nil {
		log.Println("Kafka: failed to write message: ", err)
		return
	}

	span.SetAttributes(
		attribute.String("kafka.topic", KafkaTopic),
		attribute.String("sbom.id", sbomID),
		attribute.String("sbom.project", project),
	)

	log.Printf("[Kafka] Published SBOM event for %s\n", sbomID)
}

// custom carrier to inject/extract OTel contexxt via Kafka headers
type kafkaHeaderCarrier struct {
	headers *[]kafka.Header
}

func (c kafkaHeaderCarrier) Get(key string) string {
	for _, h := range *c.headers {
		if h.Key == key {
			return string(h.Value)
		}
	}
	return ""
}

func (c kafkaHeaderCarrier) Set(key, value string) {
	*c.headers = append(*c.headers, kafka.Header{Key: key, Value: []byte(value)})
}

func (c kafkaHeaderCarrier) Keys() []string {
	keys := make([]string, len(*c.headers))
	for i, h := range *c.headers {
		keys[i] = h.Key
	}
	return keys
}
