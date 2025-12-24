package v1

import (
	"context"
	"database/sql"
	"net/http/httptest"
	"testing"

	"myesi-sbom-service-golang/models"

	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/require"
)

func TestListSBOMs_Success(t *testing.T) {
	app := newTestApp()

	orig := listSBOMService
	t.Cleanup(func() { listSBOMService = orig })

	listSBOMService = func(ctx context.Context, conn *sql.DB, project string, limit int, orgID int) ([]*models.Sbom, error) {
		require.Equal(t, "proj1", project)
		require.Equal(t, 5, limit)
		require.Equal(t, 7, orgID)
		return []*models.Sbom{
			{ID: "sb1", ProjectName: "proj1"},
		}, nil
	}

	req := httptest.NewRequest("GET", "/api/sbom/list?project_name=proj1&limit=5", nil)
	req.Header.Set("X-Organization-ID", "7")
	resp, err := app.Test(req)
	require.NoError(t, err)
	require.Equal(t, fiber.StatusOK, resp.StatusCode)
}

func TestListSBOMs_ServiceError_500(t *testing.T) {
	app := newTestApp()

	orig := listSBOMService
	t.Cleanup(func() { listSBOMService = orig })

	listSBOMService = func(ctx context.Context, conn *sql.DB, project string, limit int, orgID int) ([]*models.Sbom, error) {
		return nil, assertErr("boom")
	}

	req := httptest.NewRequest("GET", "/api/sbom/list", nil)
	req.Header.Set("X-Organization-ID", "7")
	resp, err := app.Test(req)
	require.NoError(t, err)
	require.Equal(t, fiber.StatusInternalServerError, resp.StatusCode)
}
