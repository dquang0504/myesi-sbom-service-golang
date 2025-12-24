package services

import (
	"context"
	"database/sql"
	"log"
)

// CheckAndConsumeUsage wraps the check_and_consume_usage database function and
// returns whether the requested amount can be consumed.
func CheckAndConsumeUsage(ctx context.Context, conn *sql.DB, orgID int, resource string, amount int) (bool, string, sql.NullTime, error) {
	row := conn.QueryRowContext(
		ctx,
		"SELECT allowed, message, next_reset FROM check_and_consume_usage($1,$2,$3)",
		orgID, resource, amount,
	)

	var allowed bool
	var msg string
	var periodEnd sql.NullTime
	if err := row.Scan(&allowed, &msg, &periodEnd); err != nil {
		return false, "", sql.NullTime{}, err
	}

	return allowed, msg, periodEnd, nil
}

// ReleaseUnusedUsage reverts any unused portion of a prior reservation.
func ReleaseUnusedUsage(ctx context.Context, conn *sql.DB, orgID int, resource string, reserved, succeeded int) {
	remaining := reserved - succeeded
	if remaining <= 0 {
		return
	}
	if _, err := conn.ExecContext(ctx, "SELECT revert_usage($1,$2,$3)", orgID, resource, remaining); err != nil {
		log.Printf("[USAGE][ERR] revert_usage failed: %v", err)
	}
}
