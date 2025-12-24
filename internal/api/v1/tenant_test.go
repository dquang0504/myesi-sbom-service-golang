package v1

import (
	"context"
	"database/sql"
	"errors"
	"net/http/httptest"
	"testing"

	"myesi-sbom-service-golang/internal/db"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/require"
)

func TestRequireOrgID_MissingHeader(t *testing.T) {
	app := fiber.New()
	app.Get("/", func(c *fiber.Ctx) error {
		_, err := requireOrgID(c)
		require.Error(t, err)
		ferr := err.(*fiber.Error)
		require.Equal(t, fiber.StatusUnauthorized, ferr.Code)
		return err
	})

	req := httptest.NewRequest("GET", "/", nil)
	resp, _ := app.Test(req)
	require.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)
}

func TestRequireOrgID_InvalidHeader(t *testing.T) {
	app := fiber.New()
	app.Get("/", func(c *fiber.Ctx) error {
		_, err := requireOrgID(c)
		require.Error(t, err)
		ferr := err.(*fiber.Error)
		require.Equal(t, fiber.StatusBadRequest, ferr.Code)
		return err
	})

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Organization-ID", "abc")
	resp, _ := app.Test(req)
	require.Equal(t, fiber.StatusBadRequest, resp.StatusCode)
}

func TestEnsureProjectAccessible_Success(t *testing.T) {
	sqlDB, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer sqlDB.Close()
	db.Conn = sqlDB

	mock.ExpectQuery("SELECT id\\s+FROM projects").
		WithArgs("proj", 7).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(123))

	id, err := ensureProjectAccessible(context.Background(), "proj", 7)
	require.NoError(t, err)
	require.Equal(t, 123, id)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestEnsureProjectAccessible_NotFound(t *testing.T) {
	sqlDB, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer sqlDB.Close()
	db.Conn = sqlDB

	mock.ExpectQuery("SELECT id\\s+FROM projects").
		WithArgs("proj", 7).
		WillReturnError(sql.ErrNoRows)

	_, err = ensureProjectAccessible(context.Background(), "proj", 7)
	require.Error(t, err)
	ferr := err.(*fiber.Error)
	require.Equal(t, fiber.StatusNotFound, ferr.Code)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestEnsureSBOMAccessible_NotFound(t *testing.T) {
	sqlDB, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer sqlDB.Close()
	db.Conn = sqlDB

	mock.ExpectQuery("SELECT 1\\s+FROM sboms").
		WithArgs("sbom-1", 7).
		WillReturnError(sql.ErrNoRows)

	err = ensureSBOMAccessible(context.Background(), "sbom-1", 7)
	require.Error(t, err)
	ferr := err.(*fiber.Error)
	require.Equal(t, fiber.StatusNotFound, ferr.Code)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestEnsureSBOMAccessible_DBError(t *testing.T) {
	sqlDB, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer sqlDB.Close()
	db.Conn = sqlDB

	mock.ExpectQuery("SELECT 1\\s+FROM sboms").
		WithArgs("sbom-1", 7).
		WillReturnError(errors.New("db down"))

	err = ensureSBOMAccessible(context.Background(), "sbom-1", 7)
	require.Error(t, err)
	require.Contains(t, err.Error(), "verify sbom ownership")
	require.NoError(t, mock.ExpectationsWereMet())
}
