package services

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math"
	"time"

	"myesi-sbom-service-golang/internal/db"

	"github.com/aarondl/sqlboiler/v4/boil"
	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/segmentio/kafka-go"
)

const (
	outboxStatusPending    = "pending"
	outboxStatusProcessing = "processing"
	outboxStatusRetry      = "retrying"
	outboxStatusSent       = "sent"
	outboxStatusFailed     = "failed"
	maxOutboxAttempts      = 12
)

var (
	// ErrInvalidOutboxMessage indicates the caller supplied an incomplete message.
	ErrInvalidOutboxMessage = errors.New("invalid outbox message")
)

// OutboxMessage models what gets persisted before dispatch.
type OutboxMessage struct {
	Topic     string
	EventType string
	Key       string
	Payload   interface{}
	Headers   map[string]string
	DedupKey  string
}

// EnqueueOutboxEvent stores an event for asynchronous delivery. If exec is nil
// the global DB connection is used.
func EnqueueOutboxEvent(ctx context.Context, exec boil.ContextExecutor, msg OutboxMessage) error {
	if msg.Topic == "" || msg.Payload == nil {
		return ErrInvalidOutboxMessage
	}
	if exec == nil {
		exec = db.Conn
	}

	payloadBytes, err := toJSONBytes(msg.Payload)
	if err != nil {
		return err
	}
	headerBytes, err := json.Marshal(msg.Headers)
	if err != nil {
		return err
	}

	id := uuid.New().String()
	query := `
		INSERT INTO outbox_events (id, topic, event_key, event_type, payload, headers, status, dedup_key)
		VALUES ($1,$2,$3,$4,$5,$6,$7,NULLIF($8,''))
		ON CONFLICT (dedup_key) DO NOTHING
	`
	res, err := exec.ExecContext(ctx, query,
		id,
		msg.Topic,
		nullableString(msg.Key),
		nullableString(msg.EventType),
		payloadBytes,
		nullableJSON(headerBytes),
		outboxStatusPending,
		msg.DedupKey,
	)
	if err != nil {
		return err
	}
	if msg.DedupKey != "" {
		if rows, _ := res.RowsAffected(); rows == 0 {
			// Deduplicated silently.
			return nil
		}
	}
	return nil
}

func toJSONBytes(payload interface{}) ([]byte, error) {
	switch v := payload.(type) {
	case nil:
		return nil, fmt.Errorf("payload cannot be nil")
	case []byte:
		return v, nil
	case json.RawMessage:
		return []byte(v), nil
	default:
		return json.Marshal(v)
	}
}

func nullableJSON(b []byte) interface{} {
	if len(b) == 0 || string(b) == "null" {
		return nil
	}
	return b
}

func nullableString(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}

// StartOutboxDispatcher launches the async publisher loop.
func StartOutboxDispatcher(ctx context.Context) {
	dispatcher := &outboxDispatcher{
		db:           db.Conn,
		batchSize:    20,
		pollInterval: 2 * time.Second,
	}

	go dispatcher.run(ctx)
}

type outboxDispatcher struct {
	db           *sql.DB
	batchSize    int
	pollInterval time.Duration
}

type pendingOutboxEvent struct {
	ID        string
	Topic     string
	Key       string
	EventType string
	Payload   []byte
	Headers   map[string]string
	Attempts  int
}

func (d *outboxDispatcher) run(ctx context.Context) {
	ticker := time.NewTicker(d.pollInterval)
	defer ticker.Stop()

	for {
		if err := d.dispatchBatch(ctx); err != nil {
			log.Printf("[OUTBOX][ERR] dispatch batch failed: %v", err)
		}

		select {
		case <-ctx.Done():
			log.Println("[OUTBOX] dispatcher stopping")
			return
		case <-ticker.C:
		}
	}
}

func (d *outboxDispatcher) dispatchBatch(ctx context.Context) error {
	events, err := d.claimPendingEvents(ctx)
	if err != nil {
		return err
	}
	if len(events) == 0 {
		return nil
	}

	for _, evt := range events {
		if err := d.publishEvent(ctx, evt); err != nil {
			log.Printf("[OUTBOX][WARN] publish failed id=%s: %v", evt.ID, err)
			if err := d.markFailed(ctx, evt, err); err != nil {
				log.Printf("[OUTBOX][ERR] mark failed for %s: %v", evt.ID, err)
			}
			continue
		}
		if err := d.markSent(ctx, evt); err != nil {
			log.Printf("[OUTBOX][ERR] mark sent for %s: %v", evt.ID, err)
		}
	}
	return nil
}

func (d *outboxDispatcher) claimPendingEvents(ctx context.Context) ([]pendingOutboxEvent, error) {
	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	query := `
		SELECT id, topic, event_key, event_type, payload, COALESCE(headers, '{}'::jsonb), attempts
		FROM outbox_events
		WHERE status IN ($1,$2)
		  AND (next_retry_at IS NULL OR next_retry_at <= NOW())
		ORDER BY created_at
		FOR UPDATE SKIP LOCKED
		LIMIT $3
	`

	rows, err := tx.QueryContext(ctx, query, outboxStatusPending, outboxStatusRetry, d.batchSize)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []pendingOutboxEvent
	for rows.Next() {
		var evt pendingOutboxEvent
		var headersBytes []byte
		if err := rows.Scan(&evt.ID, &evt.Topic, &evt.Key, &evt.EventType, &evt.Payload, &headersBytes, &evt.Attempts); err != nil {
			return nil, err
		}
		if len(headersBytes) > 0 {
			if err := json.Unmarshal(headersBytes, &evt.Headers); err != nil {
				log.Printf("[OUTBOX][WARN] header unmarshal for %s failed: %v", evt.ID, err)
				evt.Headers = map[string]string{}
			}
		}
		events = append(events, evt)
	}

	if len(events) == 0 {
		return nil, tx.Commit()
	}

	updateStmt := `
		UPDATE outbox_events
		SET status = $1, updated_at = NOW()
		WHERE id = ANY($2)
	`
	ids := make([]string, len(events))
	for i, evt := range events {
		ids[i] = evt.ID
	}
	if _, err := tx.ExecContext(ctx, updateStmt, outboxStatusProcessing, pq.Array(ids)); err != nil {
		return nil, err
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}

	return events, nil
}

func (d *outboxDispatcher) publishEvent(ctx context.Context, evt pendingOutboxEvent) error {
	writer, err := getKafkaWriter(evt.Topic)
	if err != nil {
		return err
	}
	headers := make([]kafka.Header, 0, len(evt.Headers))
	for k, v := range evt.Headers {
		headers = append(headers, kafka.Header{Key: k, Value: []byte(v)})
	}
	msg := kafka.Message{
		Key:     []byte(evt.Key),
		Value:   evt.Payload,
		Time:    time.Now().UTC(),
		Headers: headers,
	}
	return writer.WriteMessages(ctx, msg)
}

func (d *outboxDispatcher) markSent(ctx context.Context, evt pendingOutboxEvent) error {
	const query = `
		UPDATE outbox_events
		SET status = $1, updated_at = NOW(), next_retry_at = NULL, last_error = NULL
		WHERE id = $2
	`
	_, err := d.db.ExecContext(ctx, query, outboxStatusSent, evt.ID)
	return err
}

func (d *outboxDispatcher) markFailed(ctx context.Context, evt pendingOutboxEvent, publishErr error) error {
	status := outboxStatusRetry
	delay := exponentialDelay(evt.Attempts + 1)
	if evt.Attempts+1 >= maxOutboxAttempts {
		status = outboxStatusFailed
		delay = 0
	}
	var nextRetry interface{}
	if delay > 0 {
		nextRetry = time.Now().UTC().Add(delay)
	} else {
		nextRetry = nil
	}
	const query = `
		UPDATE outbox_events
		SET status = $1,
		    attempts = attempts + 1,
		    next_retry_at = $2,
		    updated_at = NOW(),
		    last_error = $3
		WHERE id = $4
	`
	_, err := d.db.ExecContext(ctx, query, status, nextRetry, publishErr.Error(), evt.ID)
	return err
}

func exponentialDelay(attempt int) time.Duration {
	backoff := math.Pow(2, float64(attempt))
	delay := time.Duration(backoff) * time.Second
	if delay > 5*time.Minute {
		delay = 5 * time.Minute
	}
	return delay
}
