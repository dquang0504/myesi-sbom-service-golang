package services

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"myesi-sbom-service-golang/internal/db"
	"myesi-sbom-service-golang/models"

	null "github.com/aarondl/null/v8"
	"github.com/aarondl/sqlboiler/v4/boil"
	"github.com/aarondl/sqlboiler/v4/queries/qm"
	"github.com/google/uuid"
)

func CreateSBOM(ctx context.Context, db *sql.DB, project string, sbomJSON []byte, source, objectURL string) (string, string, error) {
	id := uuid.New().String()

	summary, err := ParseSBOMSummary(sbomJSON)
	if err != nil {
		return "", "", fmt.Errorf("failed to parse SBOM summary: %w", err)
	}
	summaryBytes, _ := json.Marshal(summary)

	sbom := &models.Sbom{
		ID:          id,
		ProjectName: project,
		Source:      source,
		Sbom:        sbomJSON,
		Summary:     null.JSONFrom(summaryBytes),
		ObjectURL:   null.StringFrom(objectURL),
	}
	err = sbom.Insert(ctx, db, boil.Infer())
	return sbom.ID, "create", err
}

func UpsertSBOM(ctx context.Context, db *sql.DB, projectID int, projectName string, manifestName string, sbomJSON []byte, source, objectURL string) (string, string, error) {
	//Generate summary from sbomjson
	summary, err := ParseSBOMSummary(sbomJSON)
	if err != nil {
		return "", "", fmt.Errorf("failed to parse SBOM summary: %w", err)
	}
	summaryBytes, _ := json.Marshal(summary)

	//Check existing SBOM
	existing, err := models.Sboms(
		qm.Where("project_name=? AND manifest_name=?", projectName, manifestName),
	).One(ctx, db)

	if err == nil && existing != nil {
		existing.ProjectID = null.IntFrom(projectID)
		existing.Sbom = sbomJSON
		existing.ObjectURL = null.StringFrom(objectURL)
		existing.Summary = null.JSONFrom(summaryBytes)
		existing.Source = source
		_, err := existing.Update(ctx, db, boil.Infer())
		return existing.ID, "update", err
	}
	//Insert if not found
	// INSERT NEW
	id := uuid.New().String()
	sbom := &models.Sbom{
		ID:           id,
		ProjectID:    null.IntFrom(projectID),
		ProjectName:  projectName,
		ManifestName: null.StringFrom(manifestName),
		Source:       source,
		Sbom:         sbomJSON,
		Summary:      null.JSONFrom(summaryBytes),
		ObjectURL:    null.StringFrom(objectURL),
	}

	err = sbom.Insert(ctx, db, boil.Infer())
	return sbom.ID, "create", err
}

func GetSBOM(ctx context.Context, db *sql.DB, id string) (*models.Sbom, error) {
	return models.FindSbom(ctx, db, id)
}

func ListSBOM(ctx context.Context, db *sql.DB, project string, limit int, orgID int) ([]*models.Sbom, error) {
	queryMods := []qm.QueryMod{
		qm.OrderBy("created_at desc"),
		qm.Limit(limit),
		qm.Where(
			"EXISTS (SELECT 1 FROM projects p WHERE p.organization_id = ? AND (p.id = sboms.project_id OR p.name = sboms.project_name))",
			orgID,
		),
	}
	if project != "" {
		queryMods = append(queryMods, qm.Where("project_name = ?", project))
	}
	sboms, err := models.Sboms(queryMods...).All(ctx, db)
	if err != nil {
		return nil, err
	}
	return sboms, nil
}

// UpdateProjectSBOMMeta updates related project when new SBOM is uploaded.
func UpdateProjectSBOMMeta(ctx context.Context, db *sql.DB, project string) error {
	query := `
		UPDATE projects
		SET last_sbom_upload = NOW()
		WHERE name = $1
	`
	_, err := db.ExecContext(ctx, query, project)
	return err
}

func GetSBOMLimit(orgID int) (int, error) {
	query := `
        SELECT sp.sbom_limit
        FROM organizations o
        JOIN subscriptions s ON s.id = o.subscription_id
        JOIN subscription_plans sp ON sp.id = s.plan_id
        WHERE o.id = $1
    `
	var limit int
	err := db.Conn.QueryRowContext(context.Background(), query, orgID).Scan(&limit)
	if err != nil {
		return 0, err
	}

	return limit, nil
}

func GetSBOMCount(orgID int) (int, error) {
	query := `
        SELECT COUNT(*)
        FROM sboms s
        JOIN projects p ON p.id = s.project_id
        WHERE p.organization_id = $1
    `

	var count int
	err := db.Conn.QueryRowContext(context.Background(), query, orgID).Scan(&count)
	if err != nil {
		return 0, err
	}

	return count, nil
}
