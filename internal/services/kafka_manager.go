package services

import (
	"strings"
	"sync"

	"myesi-sbom-service-golang/internal/config"

	"github.com/segmentio/kafka-go"
)

var (
	kafkaWriterPool sync.Map
)

// getKafkaWriter returns a shared kafka.Writer per topic.
func getKafkaWriter(topic string) (*kafka.Writer, error) {
	if topic == "" {
		return nil, ErrInvalidOutboxMessage
	}
	if writer, ok := kafkaWriterPool.Load(topic); ok {
		return writer.(*kafka.Writer), nil
	}

	cfg := config.LoadConfig()
	writer := &kafka.Writer{
		Addr:         kafka.TCP(strings.Split(cfg.KafkaBroker, ",")...),
		Topic:        topic,
		Balancer:     &kafka.LeastBytes{},
		RequiredAcks: kafka.RequireAll,
		Async:        false,
	}

	actual, loaded := kafkaWriterPool.LoadOrStore(topic, writer)
	if loaded {
		_ = writer.Close()
		return actual.(*kafka.Writer), nil
	}
	return writer, nil
}

// CloseKafkaWriters drains and closes shared writers. Invoke on shutdown.
func CloseKafkaWriters() {
	kafkaWriterPool.Range(func(_, value interface{}) bool {
		if w, ok := value.(*kafka.Writer); ok {
			_ = w.Close()
		}
		return true
	})
}
