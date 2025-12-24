package v1

import (
	"context"
	"database/sql"
	"testing"

	"myesi-sbom-service-golang/internal/services"
	"myesi-sbom-service-golang/models"

	"github.com/gofiber/fiber/v2"
)

func newTestApp() *fiber.App {
	app := fiber.New()
	api := app.Group("/api")
	sbom := api.Group("/sbom")
	RegisterSBOMRoutes(sbom)
	return app
}

func resetServiceMocks(t *testing.T) {
	t.Helper()

	// restore to real implementations
	listSBOMService = services.ListSBOM
	getSBOMService = services.GetSBOM
}

// (Optional) nếu bạn vẫn muốn giữ “real refs” để gọi,
// thì dùng context.Context thay vì fiberCtx.
func servicesListSBOMReal(ctx context.Context, conn *sql.DB, project string, limit int, orgID int) ([]*models.Sbom, error) {
	return services.ListSBOM(ctx, conn, project, limit, orgID)
}

func servicesGetSBOMReal(ctx context.Context, conn *sql.DB, id string) (*models.Sbom, error) {
	return services.GetSBOM(ctx, conn, id)
}
