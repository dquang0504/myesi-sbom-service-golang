package services

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"myesi-sbom-service-golang/models"

	"github.com/aarondl/null/v8"
	"github.com/aarondl/sqlboiler/v4/boil"
	"github.com/aarondl/sqlboiler/v4/queries/qm"
	"github.com/google/uuid"
)

func CreateSBOM(ctx context.Context, db *sql.DB, project string, sbomJSON []byte, source, objectURL string)(string, error){
	id := uuid.New().String()

	summary, err := ParseSBOMSummary(sbomJSON)
	if err != nil {
        return "", fmt.Errorf("failed to parse SBOM summary: %w", err)
    }
	summaryBytes, _ := json.Marshal(summary)
	fmt.Println(summaryBytes)

	sbom := &models.Sbom{
		ID: id,
		ProjectName: project,
		Source: source,
		Sbom: sbomJSON,
		Summary: null.JSONFrom(summaryBytes),
		ObjectURL: null.StringFrom(objectURL),
	}
	err = sbom.Insert(ctx, db, boil.Infer())
	return sbom.ID, err
}

func GetSBOM(ctx context.Context, db *sql.DB, id string)(*models.Sbom, error){
	return models.FindSbom(ctx, db, id)
}

func ListSBOM(ctx context.Context, db *sql.DB, project string, limit int) ([]*models.Sbom, error){
	queryMods := []qm.QueryMod{qm.OrderBy("created_at desc"), qm.Limit(limit)}
	if project != ""{
		queryMods = append(queryMods, qm.Where("project_name = ?", project))
	}
	sboms, err := models.Sboms(queryMods...).All(ctx,db)
	if err != nil{
		return nil, err
	}
	return sboms, nil
}