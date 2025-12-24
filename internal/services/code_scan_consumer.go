package services

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/rand"
	"myesi-sbom-service-golang/internal/config"
	"myesi-sbom-service-golang/internal/db"
	"strings"
	"time"

	"github.com/segmentio/kafka-go"
)

// CodeScanEvent defines structure received from vuln-service
type CodeScanEvent struct {
	EventType string                   `json:"event_type"`
	ProjectID int                      `json:"project_id"`
	Project   string                   `json:"project"`
	Findings  []map[string]interface{} `json:"findings"`
	Manifests []map[string]interface{} `json:"manifests,omitempty"`
	Timestamp time.Time                `json:"timestamp"`
}

type eventEnvelope struct {
	Type        string          `json:"type"`
	Version     int             `json:"version"`
	OccurredAt  time.Time       `json:"occurred_at"`
	ProjectName string          `json:"project_name"`
	Data        json.RawMessage `json:"data"`
}

type codeScanEnvelopePayload struct {
	EventType   string                   `json:"event_type"`
	ProjectID   int                      `json:"project_id"`
	Project     string                   `json:"project"`
	ProjectName string                   `json:"project_name"`
	Findings    []map[string]interface{} `json:"findings"`
	Manifests   []map[string]interface{} `json:"manifests"`
}

const (
	codeScanTopic        = "code-scan-results"
	codeScanDLQTopic     = "code-scan-results.dlq"
	codeScanConsumerName = "sbom-code-scan-consumer"
)

type processingError struct {
	permanent bool
	err       error
}

func (p *processingError) Error() string {
	if p == nil || p.err == nil {
		return ""
	}
	return p.err.Error()
}

func newPermanentProcessingError(err error) error {
	if err == nil {
		return nil
	}
	return &processingError{permanent: true, err: err}
}

func isPermanentProcessingError(err error) bool {
	var pe *processingError
	if errors.As(err, &pe) {
		return pe.permanent
	}
	return false
}

type retryBackoff struct {
	attempt int
	base    time.Duration
	max     time.Duration
	rand    *rand.Rand
}

func newRetryBackoff(base, max time.Duration) *retryBackoff {
	if base <= 0 {
		base = time.Second
	}
	if max < base {
		max = base
	}
	return &retryBackoff{
		base: base,
		max:  max,
		rand: rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

func (r *retryBackoff) nextDelay() time.Duration {
	if r.attempt < 0 {
		r.attempt = 0
	}
	delay := r.base * time.Duration(1<<min(r.attempt, 5))
	if delay > r.max {
		delay = r.max
	}
	r.attempt++
	return delay + r.jitter()
}

func (r *retryBackoff) jitter() time.Duration {
	jitterWindow := r.base / 2
	if jitterWindow <= 0 {
		jitterWindow = 50 * time.Millisecond
	}
	if r.rand == nil {
		return jitterWindow
	}
	return time.Duration(r.rand.Int63n(int64(jitterWindow)))
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// StartCodeScanConsumer subscribes to "code-scan-results" and triggers SBOM generation
func StartCodeScanConsumer(ctx context.Context) {
	cfg := config.LoadConfig()
	brokers := strings.Split(cfg.KafkaBroker, ",")
	reader := kafka.NewReader(kafka.ReaderConfig{
		Brokers: brokers,
		Topic:   codeScanTopic,
		GroupID: codeScanConsumerName,
	})
	dlqWriter := &kafka.Writer{
		Addr:     kafka.TCP(brokers...),
		Topic:    codeScanDLQTopic,
		Balancer: &kafka.LeastBytes{},
	}

	log.Printf("[KAFKA] Code Scan Consumer listening on topic: %s", codeScanTopic)

	go func() {
		defer func() {
			if err := reader.Close(); err != nil {
				log.Printf("[KAFKA][ERR] reader close: %v", err)
			}
			if err := dlqWriter.Close(); err != nil {
				log.Printf("[KAFKA][ERR] dlq writer close: %v", err)
			}
		}()

		for {
			msg, err := reader.FetchMessage(ctx)
			if err != nil {
				if ctx.Err() != nil {
					log.Println("[KAFKA] Code Scan consumer stopping due to context cancellation")
					return
				}
				log.Printf("[KAFKA][ERR] fetch message: %v", err)
				time.Sleep(time.Second)
				continue
			}

			retry := newRetryBackoff(time.Second, 30*time.Second)
			for {
				if err := processCodeScanMessage(ctx, msg); err != nil {
					if isPermanentProcessingError(err) {
						log.Printf("[KAFKA][DLQ] permanent error for offset=%d: %v", msg.Offset, err)
						publishCodeScanDLQ(ctx, dlqWriter, msg, err)
						if err := commitMessage(ctx, reader, msg); err != nil {
							log.Printf("[KAFKA][ERR] commit after DLQ: %v", err)
						}
						break
					}

					delay := retry.nextDelay()
					log.Printf("[KAFKA][RETRY] transient error for offset=%d: %v (retry in %s)", msg.Offset, err, delay)
					if !sleepWithContext(ctx, delay) {
						return
					}
					continue
				}

				if err := commitMessage(ctx, reader, msg); err != nil {
					log.Printf("[KAFKA][ERR] commit after success: %v", err)
				}
				break
			}
		}
	}()
}

func processCodeScanMessage(ctx context.Context, msg kafka.Message) error {
	evt, err := decodeCodeScanEvent(msg.Value)
	if err != nil {
		return err
	}

	if err := validateCodeScanEvent(evt); err != nil {
		return newPermanentProcessingError(err)
	}

	if evt.EventType != "CODE_SCAN_DONE" {
		log.Printf("[KAFKA] ignoring unexpected event_type=%s for project_id=%d", evt.EventType, evt.ProjectID)
		return nil
	}

	log.Printf("[KAFKA] Received CODE_SCAN_DONE for project: %s", evt.Project)
	return handleCodeScanDone(ctx, evt)
}

func commitMessage(ctx context.Context, reader *kafka.Reader, msg kafka.Message) error {
	backoff := newRetryBackoff(500*time.Millisecond, 5*time.Second)
	for {
		if err := reader.CommitMessages(ctx, msg); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			delay := backoff.nextDelay()
			log.Printf("[KAFKA][ERR] commit failed (offset=%d): %v (retry in %s)", msg.Offset, err, delay)
			if !sleepWithContext(ctx, delay) {
				return ctx.Err()
			}
			continue
		}
		return nil
	}
}

func publishCodeScanDLQ(ctx context.Context, writer *kafka.Writer, msg kafka.Message, procErr error) {
	payload := map[string]interface{}{
		"error":          procErr.Error(),
		"original_topic": msg.Topic,
		"partition":      msg.Partition,
		"offset":         msg.Offset,
		"key":            string(msg.Key),
		"headers":        msg.Headers,
		"payload":        string(msg.Value),
		"timestamp":      time.Now().UTC(),
	}

	data, _ := json.Marshal(payload)
	if err := writer.WriteMessages(ctx, kafka.Message{
		Key:   msg.Key,
		Value: data,
	}); err != nil {
		log.Printf("[KAFKA][DLQ][ERR] write failed: %v", err)
	}
}

func sleepWithContext(ctx context.Context, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func validateCodeScanEvent(evt CodeScanEvent) error {
	if evt.ProjectID == 0 {
		return fmt.Errorf("missing project_id")
	}
	if strings.TrimSpace(evt.Project) == "" {
		return fmt.Errorf("missing project name")
	}
	if strings.TrimSpace(evt.EventType) == "" {
		return fmt.Errorf("missing event_type")
	}
	return nil
}

func decodeCodeScanEvent(raw []byte) (CodeScanEvent, error) {
	// Try new envelope format first.
	var env eventEnvelope
	if err := json.Unmarshal(raw, &env); err == nil && env.Type != "" && len(env.Data) > 0 {
		var payload codeScanEnvelopePayload
		if err := json.Unmarshal(env.Data, &payload); err != nil {
			return CodeScanEvent{}, newPermanentProcessingError(fmt.Errorf("invalid envelope data: %w", err))
		}

		projectName := strings.TrimSpace(payload.Project)
		if projectName == "" {
			projectName = strings.TrimSpace(payload.ProjectName)
		}
		if projectName == "" {
			projectName = strings.TrimSpace(env.ProjectName)
		}

		eventType := normalizeEventType(payload.EventType, env.Type)
		if eventType == "" {
			eventType = "CODE_SCAN_DONE"
		}

		return CodeScanEvent{
			EventType: eventType,
			ProjectID: payload.ProjectID,
			Project:   projectName,
			Findings:  payload.Findings,
			Manifests: payload.Manifests,
			Timestamp: env.OccurredAt,
		}, nil
	}

	// Fallback to legacy payload.
	var legacy struct {
		EventType   string                   `json:"event_type"`
		ProjectID   int                      `json:"project_id"`
		Project     string                   `json:"project"`
		ProjectName string                   `json:"project_name"`
		Findings    []map[string]interface{} `json:"findings"`
		Manifests   []map[string]interface{} `json:"manifests"`
		Timestamp   time.Time                `json:"timestamp"`
	}

	if err := json.Unmarshal(raw, &legacy); err != nil {
		return CodeScanEvent{}, newPermanentProcessingError(fmt.Errorf("invalid JSON payload: %w", err))
	}

	projectName := legacy.Project
	if projectName == "" {
		projectName = legacy.ProjectName
	}

	return CodeScanEvent{
		EventType: normalizeEventType(legacy.EventType, ""),
		ProjectID: legacy.ProjectID,
		Project:   projectName,
		Findings:  legacy.Findings,
		Manifests: legacy.Manifests,
		Timestamp: legacy.Timestamp,
	}, nil
}

func normalizeEventType(primary, fallback string) string {
	candidate := strings.TrimSpace(primary)
	if candidate == "" {
		candidate = strings.TrimSpace(fallback)
	}
	candidate = strings.ToUpper(candidate)
	candidate = strings.ReplaceAll(candidate, ".", "_")
	return candidate
}

func handleCodeScanDone(ctx context.Context, evt CodeScanEvent) error {
	project := evt.Project
	projectID := evt.ProjectID
	codeFindingsCount := len(evt.Findings)

	// -----------------------------------------------------
	// 1) Load orgID
	// -----------------------------------------------------
	var orgID int
	err := db.Conn.QueryRowContext(ctx,
		"SELECT organization_id FROM projects WHERE id=$1",
		projectID,
	).Scan(&orgID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			log.Printf(
				"[SBOM][ERR] Could not determine project organization for project %d",
				projectID,
			)
			publishKafkaWarning(
				ctx,
				"sbom.org_lookup_failed",
				project,
				projectID,
				fmt.Sprintf("Could not determine project organization for project %d", projectID),
			)
			return newPermanentProcessingError(
				fmt.Errorf("could not determine project organization for project %d", projectID),
			)
		}
		return fmt.Errorf("load org id: %w", err)
	}

	// -----------------------------------------------------
	// 2) Count SBOMs to create
	// -----------------------------------------------------
	toCreate := 0
	for _, m := range evt.Manifests {
		if contentStr, _ := m["content"].(string); contentStr != "" {
			toCreate++
		}
	}
	if toCreate == 0 {
		toCreate = 1
	}

	// -----------------------------------------------------
	// 3) Check quota before creation
	// -----------------------------------------------------
	allowed, msg, _, err := CheckAndConsumeUsage(ctx, db.Conn, orgID, "sbom_upload", toCreate)
	if err != nil {
		log.Printf("[USAGE][ERR] usage check failed: %v", err)
		publishKafkaWarning(ctx, "sbom.limit_check_failed", project, projectID, fmt.Sprintf("Usage check failed: %v", err))
		return err
	}
	if !allowed {
		log.Printf("[LIMIT] SBOM skipped for %s — %s", project, msg)
		publishKafkaWarning(ctx, "sbom.limit_reached", project, projectID, msg)
		return nil
	}

	reserved := toCreate
	successful := 0
	defer func() {
		ReleaseUnusedUsage(ctx, db.Conn, orgID, "sbom_upload", reserved, successful)
	}()

	// -----------------------------------------------------
	// 4) Generate SBOMs from manifests
	// -----------------------------------------------------
	var createdSBOMs []map[string]interface{}
	manifestName := ""

	for _, m := range evt.Manifests {
		name, _ := m["name"].(string)
		contentStr, _ := m["content"].(string)
		if contentStr == "" {
			continue
		}
		manifestName = name

		sbomRes, err := ParseManifest(ctx, project, manifestName, []byte(contentStr))
		if err != nil {
			log.Printf("[SBOM][ERR] ParseManifest failed for %s: %v", name, err)
			continue
		}

		id, _, err := UpsertSBOM(ctx, db.Conn, projectID, project, manifestName, sbomRes.Data, "auto-code-scan", "")
		if err != nil {
			log.Printf("[SBOM][ERR] UpsertSBOM failed for %s: %v", name, err)
			continue
		}
		successful++

		comps := ExtractComponents(sbomRes.Data)
		createdSBOMs = append(createdSBOMs, map[string]interface{}{
			"id":         id,
			"components": comps,
		})
		log.Printf("[SBOM] Created SBOM %s for project %s (manifest=%s)", id, project, name)
	}

	// -----------------------------------------------------
	// 5) Fallback: build SBOM from findings
	// -----------------------------------------------------
	if len(createdSBOMs) == 0 && len(evt.Findings) > 0 {
		sbomMap := BuildSBOMFromFindings(evt.Findings)
		sbomData, _ := json.Marshal(sbomMap)

		url, _ := UploadSBOMJSON(ctx, orgID, projectID, project, manifestName, sbomData)

		id, _, err := UpsertSBOM(ctx, db.Conn, projectID, project, manifestName, sbomData, "auto-code-scan", url)
		if err != nil {
			log.Printf("[SBOM][ERR] fallback upsert failed: %v", err)
			return err
		}
		successful++

		comps := ExtractComponents(sbomData)
		createdSBOMs = append(createdSBOMs, map[string]interface{}{
			"id":         id,
			"components": comps,
		})
		log.Printf("[SBOM] Fallback SBOM created for project %s", project)
	}

	// -----------------------------------------------------
	// 6) Queue batch event
	// -----------------------------------------------------
	if err := queueSBOMBatchEvent(ctx, evt, orgID, codeFindingsCount, createdSBOMs); err != nil {
		return err
	}

	log.Printf("[KAFKA] Queued batch event for %d SBOM(s) in project %s", len(createdSBOMs), project)
	return nil
}

// Helper: publish warning/limit event
func publishKafkaWarning(ctx context.Context, eventType, project string, projectID int, msg string) {
	event := map[string]interface{}{
		"type":       eventType,
		"project":    project,
		"project_id": projectID,
		"message":    msg,
		"timestamp":  time.Now().UTC(),
	}

	if err := EnqueueOutboxEvent(ctx, nil, OutboxMessage{
		Topic:     KafkaTopic,
		EventType: eventType,
		Key:       fmt.Sprintf("project-%d", projectID),
		Payload:   event,
	}); err != nil {
		log.Printf("[OUTBOX][WARN] failed to enqueue warning event: %v", err)
	}
}

func queueSBOMBatchEvent(ctx context.Context, evt CodeScanEvent, orgID int, codeFindingsCount int, records []map[string]interface{}) error {
	event := map[string]interface{}{
		"type":                        "sbom.batch_created",
		"project":                     evt.Project,
		"project_id":                  evt.ProjectID,
		"organization_id":             orgID,
		"source":                      "project_scan",
		"code_findings_count":         codeFindingsCount,
		"project_scan_quota_consumed": true,
		"timestamp":                   time.Now().UTC(),
		"sbom_records":                records,
	}

	dedupKey := fmt.Sprintf("sbom-batch:%d:%s", evt.ProjectID, evt.Timestamp.UTC().Format(time.RFC3339Nano))
	return EnqueueOutboxEvent(ctx, nil, OutboxMessage{
		Topic:     KafkaTopic,
		EventType: "sbom.batch_created",
		Key:       fmt.Sprintf("project-%d", evt.ProjectID),
		Payload:   event,
		DedupKey:  dedupKey,
	})
}

// BuildSBOMFromFindings constructs minimal SBOM from code scan
func BuildSBOMFromFindings(findings []map[string]interface{}) map[string]interface{} {
	comps := []map[string]interface{}{}
	for _, f := range findings {
		comps = append(comps, map[string]interface{}{
			"name":     f["check_id"],
			"version":  "N/A",
			"file":     f["path"],
			"severity": f["severity"],
			"message":  f["message"],
		})
	}
	return map[string]interface{}{
		"bomFormat":   "CycloneDX",
		"specVersion": "1.4",
		"components":  comps,
	}
}
