package services

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
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

// StartCodeScanConsumer subscribes to "code-scan-results" and triggers SBOM generation
func StartCodeScanConsumer() {
	cfg := config.LoadConfig()
	reader := kafka.NewReader(kafka.ReaderConfig{
		Brokers: strings.Split(cfg.KafkaBroker, ","),
		Topic:   "code-scan-results",
		GroupID: "sbom-code-scan-consumer",
	})

	log.Println("[KAFKA] Code Scan Consumer listening on topic: code-scan-results")

	go func() {
		for {
			msg, err := reader.ReadMessage(context.Background())
			if err != nil {
				log.Printf("[KAFKA][ERR] read: %v", err)
				continue
			}

			var evt CodeScanEvent
			if err := json.Unmarshal(msg.Value, &evt); err != nil {
				log.Printf("[KAFKA][ERR] unmarshal: %v", err)
				continue
			}

			if evt.EventType == "CODE_SCAN_DONE" {
				log.Printf("[KAFKA] Received CODE_SCAN_DONE for project: %s", evt.Project)
				handleCodeScanDone(evt)
			}
		}
	}()
}

func handleCodeScanDone(evt CodeScanEvent) {
	ctx := context.Background()
	project := evt.Project
	projectID := evt.ProjectID

	// -----------------------------------------------------
	// 1) Load orgID
	// -----------------------------------------------------
	var orgID int
	err := db.Conn.QueryRowContext(ctx,
		"SELECT organization_id FROM projects WHERE id=$1",
		projectID,
	).Scan(&orgID)
	if err != nil {
		log.Printf("[SBOM][ERR] cannot load orgID: %v", err)
		publishKafkaWarning("sbom.org_lookup_failed", project, projectID, fmt.Sprintf("Could not determine project organization: %v", err))
		return
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
	var allowed bool
	var msg string
	var periodEnd time.Time
	row := db.Conn.QueryRowContext(
		ctx,
		"SELECT allowed, message, next_reset FROM check_and_consume_usage($1,$2,$3)",
		orgID, "sbom_upload", toCreate,
	)
	if err := row.Scan(&allowed, &msg, &periodEnd); err != nil {
		log.Printf("[USAGE][ERR] usage check failed: %v", err)
		publishKafkaWarning("sbom.limit_check_failed", project, projectID, fmt.Sprintf("Usage check failed: %v", err))
		return
	}
	if !allowed {
		log.Printf("[LIMIT] SBOM skipped for %s — %s", project, msg)
		publishKafkaWarning("sbom.limit_reached", project, projectID, msg)
		return
	}

	// Helper to revert usage if SBOM creation fails
	revertUsage := func() {
		_, _ = db.Conn.ExecContext(ctx, "SELECT revert_usage($1,$2,$3)", orgID, "sbom_upload", toCreate)
	}

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
			revertUsage()
			continue
		}

		id, _, err := UpsertSBOM(ctx, db.Conn, projectID, project, manifestName, sbomRes.Data, "auto-code-scan", "")
		if err != nil {
			log.Printf("[SBOM][ERR] UpsertSBOM failed for %s: %v", name, err)
			revertUsage()
			continue
		}

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

		url, _ := UploadSBOMJSON(ctx, db.Conn, projectID, project, manifestName, sbomData, []byte(`{}`))

		id, _, err := UpsertSBOM(ctx, db.Conn, projectID, project, manifestName, sbomData, "auto-fallback", url)
		if err != nil {
			log.Printf("[SBOM][ERR] fallback upsert failed: %v", err)
			revertUsage()
			return
		}

		comps := ExtractComponents(sbomData)
		createdSBOMs = append(createdSBOMs, map[string]interface{}{
			"id":         id,
			"components": comps,
		})
		log.Printf("[SBOM] Fallback SBOM created for project %s", project)
	}

	// -----------------------------------------------------
	// 6) Publish batch event
	// -----------------------------------------------------
	kafkaWriter := kafka.Writer{
		Addr:  kafka.TCP(strings.Split(config.LoadConfig().KafkaBroker, ",")...),
		Topic: "sbom-events",
	}
	defer kafkaWriter.Close()

	event := map[string]interface{}{
		"type":         "sbom.batch_created",
		"project":      project,
		"project_id":   projectID,
		"timestamp":    time.Now().UTC(),
		"sbom_records": createdSBOMs,
	}

	data, _ := json.Marshal(event)
	if err := kafkaWriter.WriteMessages(ctx, kafka.Message{
		Key:   []byte(project),
		Value: data,
	}); err != nil {
		log.Printf("[KAFKA][ERR] publish sbom batch: %v", err)
		revertUsage()
		return
	}

	log.Printf("[KAFKA] Published batch event for %d SBOM(s) in project %s", len(createdSBOMs), project)
}

// Helper: publish warning/limit event
func publishKafkaWarning(eventType, project string, projectID int, msg string) {
	kafkaWriter := kafka.Writer{
		Addr:  kafka.TCP(strings.Split(config.LoadConfig().KafkaBroker, ",")...),
		Topic: "sbom-events",
	}
	defer kafkaWriter.Close()

	event := map[string]interface{}{
		"type":       eventType,
		"project":    project,
		"project_id": projectID,
		"message":    msg,
		"timestamp":  time.Now().UTC(),
	}

	data, _ := json.Marshal(event)
	_ = kafkaWriter.WriteMessages(context.Background(), kafka.Message{
		Key:   []byte(project),
		Value: data,
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
