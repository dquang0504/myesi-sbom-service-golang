package services

import (
	"context"
	"fmt"
	"time"

	"github.com/aarondl/sqlboiler/v4/boil"
)

const notificationTopic = "notification-events"

// QueueScanSummary sends a project scan summary event to notification service via the outbox.
func QueueScanSummary(ctx context.Context, exec boil.ContextExecutor, orgID int, project string, vulns int, codeFindings int, status string) error {
	payload := map[string]interface{}{
		"project":       project,
		"vulns":         vulns,
		"code_findings": codeFindings,
		"status":        status,
		"action_url":    "/developer/vulnerabilities",
		"target_role":   "developer",
	}

	evt := map[string]interface{}{
		"type":            "project.scan.summary",
		"organization_id": orgID,
		"severity":        "info",
		"payload":         payload,
		"occurred_at":     time.Now().UTC(),
	}

	return EnqueueOutboxEvent(ctx, exec, OutboxMessage{
		Topic:     notificationTopic,
		EventType: "project.scan.summary",
		Key:       fmt.Sprintf("org-%d-scan-%s", orgID, project),
		Payload:   evt,
	})
}

// QueueManualSBOMSummary notifies about manual SBOM upload/scan.
func QueueManualSBOMSummary(ctx context.Context, exec boil.ContextExecutor, orgID int, project string, components int, vulns int, status string) error {
	payload := map[string]interface{}{
		"project":     project,
		"components":  components,
		"vulns":       vulns,
		"status":      status,
		"action_url":  "/developer/assignments",
		"target_role": "developer",
	}

	evt := map[string]interface{}{
		"type":            "sbom.scan.summary",
		"organization_id": orgID,
		"severity":        "info",
		"payload":         payload,
		"occurred_at":     time.Now().UTC(),
	}

	return EnqueueOutboxEvent(ctx, exec, OutboxMessage{
		Topic:     notificationTopic,
		EventType: "sbom.scan.summary",
		Key:       fmt.Sprintf("org-%d-sbom-%s", orgID, project),
		Payload:   evt,
	})
}
