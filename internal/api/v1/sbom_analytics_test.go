package v1

import (
	"net/http/httptest"
	"testing"
	"time"

	"myesi-sbom-service-golang/internal/db"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/require"
)

func TestSBOMAnalytics_Success(t *testing.T) {
	app := newTestApp()

	sqlDB, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer sqlDB.Close()
	db.Conn = sqlDB

	// scannedToday
	mock.ExpectQuery(`SELECT COUNT\(\*\) FROM sboms s WHERE`).
		WithArgs(7).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(5))

	// trend query
	rows := sqlmock.NewRows([]string{"date", "scanned", "uploaded"}).
		AddRow(time.Date(2025, 12, 1, 0, 0, 0, 0, time.UTC), 2, 1).
		AddRow(time.Date(2025, 12, 2, 0, 0, 0, 0, time.UTC), 3, 0)

	mock.ExpectQuery(`SELECT\s+s\.created_at::date AS date,`).
		WithArgs(7).
		WillReturnRows(rows)

	req := httptest.NewRequest("GET", "/api/sbom/analytics", nil)
	req.Header.Set("X-Organization-ID", "7")
	resp, err := app.Test(req)
	require.NoError(t, err)
	require.Equal(t, fiber.StatusOK, resp.StatusCode)

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestSBOMAnalytics_DBErrorOnScannedToday_500(t *testing.T) {
	app := newTestApp()

	sqlDB, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer sqlDB.Close()
	db.Conn = sqlDB

	mock.ExpectQuery(`SELECT COUNT\(\*\) FROM sboms s WHERE`).
		WithArgs(7).
		WillReturnError(assertErr("db err"))

	req := httptest.NewRequest("GET", "/api/sbom/analytics", nil)
	req.Header.Set("X-Organization-ID", "7")
	resp, err := app.Test(req)
	require.NoError(t, err)
	require.Equal(t, fiber.StatusInternalServerError, resp.StatusCode)

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestSBOMAnalytics_DBErrorOnTrendQuery_500(t *testing.T) {
	app := newTestApp()

	sqlDB, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer sqlDB.Close()
	db.Conn = sqlDB

	mock.ExpectQuery(`SELECT COUNT\(\*\) FROM sboms s WHERE`).
		WithArgs(7).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))

	mock.ExpectQuery(`SELECT\s+s\.created_at::date AS date,`).
		WithArgs(7).
		WillReturnError(assertErr("trend err"))

	req := httptest.NewRequest("GET", "/api/sbom/analytics", nil)
	req.Header.Set("X-Organization-ID", "7")
	resp, err := app.Test(req)
	require.NoError(t, err)
	require.Equal(t, fiber.StatusInternalServerError, resp.StatusCode)

	require.NoError(t, mock.ExpectationsWereMet())
}
