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

func TestRecentSBOMs_Success_DefaultPaging(t *testing.T) {
	app := newTestApp()

	sqlDB, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer sqlDB.Close()
	db.Conn = sqlDB

	// count query
	mock.ExpectQuery(`SELECT COUNT\(\*\) FROM sboms s WHERE`).
		WithArgs(7).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(2))

	// list query
	createdAt := time.Date(2025, 12, 14, 10, 0, 0, 0, time.UTC)
	rows := sqlmock.NewRows([]string{
		"id", "project_name", "manifest_name", "object_url", "created_at", "source", "findings",
	}).
		AddRow("sb1", "proj1", "go.mod", "db://x", createdAt, "upload", 3).
		AddRow("sb2", "proj1", "package-lock.json", "", createdAt.Add(time.Minute), "auto-code-scan", 0)

	mock.ExpectQuery(`SELECT id, project_name, manifest_name, object_url, created_at, source,`).
		WithArgs(7, 10, 0). // default page_size=10, offset=0
		WillReturnRows(rows)

	req := httptest.NewRequest("GET", "/api/sbom/recent", nil)
	req.Header.Set("X-Organization-ID", "7")
	resp, err := app.Test(req)
	require.NoError(t, err)
	require.Equal(t, fiber.StatusOK, resp.StatusCode)

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestRecentSBOMs_WithFilters_Project_Source_Search(t *testing.T) {
	app := newTestApp()

	sqlDB, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer sqlDB.Close()
	db.Conn = sqlDB

	// When project + source + q are present, args order is:
	// orgID, project, source, "%q%", pageSize, offset
	mock.ExpectQuery(`SELECT COUNT\(\*\) FROM sboms s WHERE`).
		WithArgs(7, "proj1", "manual", "%lock%").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))

	mock.ExpectQuery(`SELECT id, project_name, manifest_name, object_url, created_at, source,`).
		WithArgs(7, "proj1", "manual", "%lock%", 12, 12). // page=2,page_size=12 => offset=12
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "project_name", "manifest_name", "object_url", "created_at", "source", "findings",
		}))

	req := httptest.NewRequest("GET", "/api/sbom/recent?project_name=proj1&source=manual&q=lock&page=2&page_size=12", nil)
	req.Header.Set("X-Organization-ID", "7")
	resp, err := app.Test(req)
	require.NoError(t, err)
	require.Equal(t, fiber.StatusOK, resp.StatusCode)

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestRecentSBOMs_InvalidOrgHeader_401_Or_400(t *testing.T) {
	app := newTestApp()

	req := httptest.NewRequest("GET", "/api/sbom/recent", nil)
	// no org header
	resp, err := app.Test(req)
	require.NoError(t, err)
	require.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)

	req2 := httptest.NewRequest("GET", "/api/sbom/recent", nil)
	req2.Header.Set("X-Organization-ID", "abc")
	resp2, err := app.Test(req2)
	require.NoError(t, err)
	require.Equal(t, fiber.StatusBadRequest, resp2.StatusCode)
}

func TestRecentSBOMs_DBCountError_500(t *testing.T) {
	app := newTestApp()

	sqlDB, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer sqlDB.Close()
	db.Conn = sqlDB

	mock.ExpectQuery(`SELECT COUNT\(\*\) FROM sboms s WHERE`).
		WithArgs(7).
		WillReturnError(assertErr("db down"))

	req := httptest.NewRequest("GET", "/api/sbom/recent", nil)
	req.Header.Set("X-Organization-ID", "7")
	resp, err := app.Test(req)
	require.NoError(t, err)
	require.Equal(t, fiber.StatusInternalServerError, resp.StatusCode)

	require.NoError(t, mock.ExpectationsWereMet())
}

// tiny helper to avoid importing errors everywhere
type assertErr string

func (e assertErr) Error() string { return string(e) }
