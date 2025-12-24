package v1

import (
	"context"
	"database/sql"
	"net/http/httptest"
	"testing"

	"myesi-sbom-service-golang/internal/db"
	"myesi-sbom-service-golang/models"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/require"
)

func TestGetSBOM_Success(t *testing.T) {
	app := newTestApp()

	sqlDB, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer sqlDB.Close()
	db.Conn = sqlDB

	mock.ExpectQuery(`SELECT 1\s+FROM sboms s`).
		WithArgs("sb1", 7).
		WillReturnRows(sqlmock.NewRows([]string{"1"}).AddRow(1))

	orig := getSBOMService
	t.Cleanup(func() { getSBOMService = orig })
	getSBOMService = func(ctx context.Context, conn *sql.DB, id string) (*models.Sbom, error) {
		return &models.Sbom{ID: id, ProjectName: "proj1"}, nil
	}

	req := httptest.NewRequest("GET", "/api/sbom/sb1", nil)
	req.Header.Set("X-Organization-ID", "7")
	resp, err := app.Test(req)
	require.NoError(t, err)
	require.Equal(t, fiber.StatusOK, resp.StatusCode)

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestGetSBOM_NotAccessible_404(t *testing.T) {
	app := newTestApp()

	sqlDB, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer sqlDB.Close()
	db.Conn = sqlDB

	mock.ExpectQuery(`SELECT 1\s+FROM sboms s`).
		WithArgs("sb1", 7).
		WillReturnError(sql.ErrNoRows)

	req := httptest.NewRequest("GET", "/api/sbom/sb1", nil)
	req.Header.Set("X-Organization-ID", "7")
	resp, err := app.Test(req)
	require.NoError(t, err)
	require.Equal(t, fiber.StatusNotFound, resp.StatusCode)

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestGetSBOM_ServiceError_404(t *testing.T) {
	app := newTestApp()

	sqlDB, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer sqlDB.Close()
	db.Conn = sqlDB

	mock.ExpectQuery(`SELECT 1\s+FROM sboms s`).
		WithArgs("sb1", 7).
		WillReturnRows(sqlmock.NewRows([]string{"1"}).AddRow(1))

	orig := getSBOMService
	t.Cleanup(func() { getSBOMService = orig })
	getSBOMService = func(ctx context.Context, conn *sql.DB, id string) (*models.Sbom, error) {
		return nil, assertErr("not found")
	}

	req := httptest.NewRequest("GET", "/api/sbom/sb1", nil)
	req.Header.Set("X-Organization-ID", "7")
	resp, err := app.Test(req)
	require.NoError(t, err)
	require.Equal(t, fiber.StatusNotFound, resp.StatusCode)

	require.NoError(t, mock.ExpectationsWereMet())
}
