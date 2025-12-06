package services

import (
	"context"
	"encoding/json"
	"log"
	"myesi-sbom-service-golang/internal/config"
	"strings"
	"time"

	"github.com/segmentio/kafka-go"
)

const notificationTopic = "notification-events"

// PublishScanSummary sends a project scan summary event to notification service.
func PublishScanSummary(orgID int, project string, vulns int, codeFindings int, status string) {
	cfg := config.LoadConfig()
	writer := kafka.Writer{
		Addr:  kafka.TCP(strings.Split(cfg.KafkaBroker, ",")...),
		Topic: notificationTopic,
	}
	defer writer.Close()

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

	data, err := json.Marshal(evt)
	if err != nil {
		log.Printf("[NOTIFY] marshal scan summary failed: %v", err)
		return
	}

	msg := kafka.Message{
		Key:   []byte(project),
		Value: data,
		Time:  time.Now().UTC(),
	}

	if err := writer.WriteMessages(context.Background(), msg); err != nil {
		log.Printf("[NOTIFY] publish scan summary failed: %v", err)
	}
}

// PublishManualSBOMSummary notifies about manual SBOM upload/scan.
func PublishManualSBOMSummary(orgID int, project string, components int, vulns int, status string) {
	cfg := config.LoadConfig()
	writer := kafka.Writer{
		Addr:  kafka.TCP(strings.Split(cfg.KafkaBroker, ",")...),
		Topic: notificationTopic,
	}
	defer writer.Close()

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

	data, err := json.Marshal(evt)
	if err != nil {
		log.Printf("[NOTIFY] marshal sbom summary failed: %v", err)
		return
	}

	msg := kafka.Message{
		Key:   []byte(project),
		Value: data,
		Time:  time.Now().UTC(),
	}

	if err := writer.WriteMessages(context.Background(), msg); err != nil {
		log.Printf("[NOTIFY] publish sbom summary failed: %v", err)
	}
}
