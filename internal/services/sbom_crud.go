package services

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
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

func UpsertSBOM(ctx context.Context, db *sql.DB, project string, sbomJSON []byte, source, objectURL string) (string, string, error) {
	//Generate summary from sbomjson
	summary, err := ParseSBOMSummary(sbomJSON)
	if err != nil {
		return "", "", fmt.Errorf("failed to parse SBOM summary: %w", err)
	}
	summaryBytes, _ := json.Marshal(summary)

	//Check existing SBOM
	existing, err := models.Sboms(qm.Where("project_name=?", project)).One(ctx, db)
	if err == nil && existing != nil {
		//Update SBOM JSON, summary, object URL, last_updated timestamp
		existing.Sbom = sbomJSON
		existing.ObjectURL = null.StringFrom(objectURL)
		existing.Summary = null.JSONFrom(summaryBytes)
		_, err := existing.Update(ctx, db, boil.Infer())

		_ = UpdateProjectSBOMMeta(ctx, db, project)
		return existing.ID, "update", err
	}
	//Insert if not found
	return CreateSBOM(ctx, db, project, sbomJSON, source, objectURL)
}

func GetSBOM(ctx context.Context, db *sql.DB, id string) (*models.Sbom, error) {
	return models.FindSbom(ctx, db, id)
}

func ListSBOM(ctx context.Context, db *sql.DB, project string, limit int) ([]*models.Sbom, error) {
	queryMods := []qm.QueryMod{qm.OrderBy("created_at desc"), qm.Limit(limit)}
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
