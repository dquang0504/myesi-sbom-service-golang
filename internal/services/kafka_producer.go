package services

import (
	"context"
	"log"

	"github.com/aarondl/sqlboiler/v4/boil"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
)

// Kafka config
const (
	KafkaTopic = "sbom-events"
)

// SBOMEvent struct is the payload which gets sent to Vulnerability Service
type SBOMEvent struct {
	SBOMID         string              `json:"sbom_id"`
	Project        string              `json:"project_name"`
	ProjectID      int                 `json:"project_id,omitempty"`
	OrganizationID int                 `json:"organization_id,omitempty"`
	Source         string              `json:"source,omitempty"`
	Components     []map[string]string `json:"components"`
}

// QueueSBOMEvent persists an event for async publishing via the outbox.
func QueueSBOMEvent(ctx context.Context, exec boil.ContextExecutor, sbomID string, project string, projectID int, orgID int, comps []map[string]string, source string) error {
	ctx, span := otel.Tracer("sbom-service").Start(ctx, "QueueSBOMEvent")
	defer span.End()

	headers := map[string]string{}
	if propagator := otel.GetTextMapPropagator(); propagator != nil {
		propagator.Inject(ctx, propagation.MapCarrier(headers))
	}

	event := SBOMEvent{
		SBOMID:         sbomID,
		Project:        project,
		ProjectID:      projectID,
		OrganizationID: orgID,
		Source:         source,
		Components:     comps,
	}

	err := EnqueueOutboxEvent(ctx, exec, OutboxMessage{
		Topic:     KafkaTopic,
		EventType: "sbom.created",
		Key:       sbomID,
		Payload:   event,
		Headers:   headers,
	})
	if err != nil {
		log.Printf("[OUTBOX][ERR] queue sbom event failed: %v", err)
	}
	return err
}
