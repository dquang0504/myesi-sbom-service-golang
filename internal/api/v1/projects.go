package v1

import (
	"database/sql"
	"encoding/json"
	"myesi-sbom-service-golang/internal/db"
	"myesi-sbom-service-golang/models"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/aarondl/null/v8"
	"github.com/aarondl/sqlboiler/v4/boil"
	"github.com/aarondl/sqlboiler/v4/queries/qm"
	"github.com/aarondl/sqlboiler/v4/types"
	"github.com/ericlagergren/decimal"
	"github.com/gofiber/fiber/v2"
)

func nullableString(ns null.String) *string {
	if ns.Valid {
		return &ns.String
	}
	return nil
}

func nullableInt(ni null.Int) *int {
	if ni.Valid {
		v := int(ni.Int)
		return &v
	}
	return nil
}

// RegisterProjectRoutes mounts CRUD routes for projects table.
func RegisterProjectRoutes(r fiber.Router) {
	r.Get("/", project_getAll)
	r.Post("/", project_create)
	r.Post("/import/github", importGithubProjects)
	r.Get("/top-languages", project_topLanguages)
	r.Put("/:id", project_update)
	r.Delete("/:id", project_delete)
	r.Get("/:id", project_getOne)
}

// List all projects
func project_getAll(c *fiber.Ctx) error {
	page, _ := strconv.Atoi(c.Query("page", "1"))
	if page < 1 {
		page = 1
	}
	pageSize, _ := strconv.Atoi(c.Query("page_size", "12"))
	if pageSize <= 0 || pageSize > 50 {
		pageSize = 12
	}
	offset := (page - 1) * pageSize

	search := strings.TrimSpace(c.Query("q"))
	source := strings.ToLower(strings.TrimSpace(c.Query("source")))
	language := strings.TrimSpace(c.Query("language"))
	findings := strings.ToLower(strings.TrimSpace(c.Query("findings")))

	baseMods := []qm.QueryMod{}

	if search != "" {
		baseMods = append(baseMods, qm.Where("name ILIKE ?", "%"+search+"%"))
	}

	if source != "" && source != "all" {
		baseMods = append(baseMods, qm.Where("LOWER(source_type) = ?", source))
	}

	if language != "" && language != "all" {
		baseMods = append(baseMods, qm.Where("github_language::text ILIKE ?", "%"+language+"%"))
	}
	if findings == "with" {
		baseMods = append(baseMods, qm.Where("COALESCE(total_vulnerabilities,0) > 0"))
	} else if findings == "without" {
		baseMods = append(baseMods, qm.Where("COALESCE(total_vulnerabilities,0) = 0"))
	}

	total, err := models.Projects(baseMods...).Count(c.Context(), db.Conn)
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}

	listMods := append([]qm.QueryMod{
		qm.OrderBy("created_at DESC"),
		qm.Limit(pageSize),
		qm.Offset(offset),
	}, baseMods...)

	list, err := models.Projects(listMods...).All(c.Context(), db.Conn)
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}

	type ProjectDTO struct {
		ID                   int64      `json:"id"`
		Name                 string     `json:"name"`
		Description          *string    `json:"description,omitempty"`
		SourceType           *string    `json:"source_type,omitempty"`
		RepoURL              *string    `json:"repo_url,omitempty"`
		GithubFullName       *string    `json:"github_full_name,omitempty"`
		GithubDefaultBranch  *string    `json:"github_default_branch,omitempty"`
		GithubVisibility     *string    `json:"github_visibility,omitempty"`
		GithubLastSync       *time.Time `json:"github_last_sync,omitempty"`
		LastSbomUpload       *time.Time `json:"last_sbom_upload,omitempty"`
		LastVulnScan         *time.Time `json:"last_vuln_scan,omitempty"`
		AvgRiskScore         *float64   `json:"avg_risk_score,omitempty"`
		TotalVulnerabilities *int       `json:"total_vulnerabilities,omitempty"`
		OrganizationID       *int       `json:"organization_id,omitempty"`
		Languages            []string   `json:"languages,omitempty"`
		PrimaryLanguage      *string    `json:"primary_language,omitempty"`
		CreatedAt            *time.Time `json:"created_at,omitempty"`
	}

	resp := make([]ProjectDTO, 0, len(list))
	for _, p := range list {
		var langs []string
		if p.GithubLanguage.Valid {
			_ = json.Unmarshal(p.GithubLanguage.JSON, &langs)
		}

		var primary *string
		if len(langs) > 0 {
			primary = &langs[0]
		}

		dto := ProjectDTO{
			ID:                   int64(p.ID),
			Name:                 p.Name,
			Description:          nullableString(p.Description),
			SourceType:           nullableString(p.SourceType),
			RepoURL:              nullableString(p.RepoURL),
			GithubFullName:       nullableString(p.GithubFullName),
			GithubDefaultBranch:  nullableString(p.GithubDefaultBranch),
			GithubVisibility:     nullableString(p.GithubVisibility),
			Languages:            langs,
			PrimaryLanguage:      primary,
			TotalVulnerabilities: nullableInt(p.TotalVulnerabilities),
			OrganizationID:       nullableInt(p.OrganizationID),
		}

		if p.GithubLastSync.Valid {
			dto.GithubLastSync = &p.GithubLastSync.Time
		}
		if p.LastSbomUpload.Valid {
			dto.LastSbomUpload = &p.LastSbomUpload.Time
		}
		if p.LastVulnScan.Valid {
			dto.LastVulnScan = &p.LastVulnScan.Time
		}
		if p.AvgRiskScore.Big != nil {
			f, _ := p.AvgRiskScore.Big.Float64()
			dto.AvgRiskScore = &f
		}
		if p.CreatedAt.Valid {
			dto.CreatedAt = &p.CreatedAt.Time
		}

		resp = append(resp, dto)
	}

	return c.JSON(fiber.Map{
		"data":      resp,
		"page":      page,
		"page_size": pageSize,
		"total":     total,
	})
}

// Get a single project
func project_getOne(c *fiber.Ctx) error {
	id, err := c.ParamsInt("id")
	if err != nil || id == 0 {
		return fiber.NewError(fiber.StatusBadRequest, "invalid project id")
	}

	project, err := models.FindProject(c.Context(), db.Conn, id)
	if err == sql.ErrNoRows {
		return fiber.NewError(fiber.StatusNotFound, "project not found")
	} else if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}
	return c.JSON(project)
}

// Create new project
func project_create(c *fiber.Ctx) error {
	var payload struct {
		Name           string  `json:"name"`
		Description    *string `json:"description"`
		OwnerID        *int    `json:"owner_id"`
		RepoURL        *string `json:"repo_url"`
		OrganizationID int     `json:"organization_id"`
	}
	if err := c.BodyParser(&payload); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid json payload")
	}
	if payload.Name == "" {
		return fiber.NewError(fiber.StatusBadRequest, "project name required")
	}

	p := &models.Project{
		Name:           payload.Name,
		Description:    null.StringFromPtr(payload.Description),
		RepoURL:        null.StringFromPtr(payload.RepoURL),
		CreatedAt:      null.TimeFrom(time.Now()),
		OrganizationID: null.IntFrom(payload.OrganizationID),
	}
	if payload.OwnerID != nil {
		p.OwnerID = null.IntFrom(*payload.OwnerID)
	}

	if err := p.Insert(c.Context(), db.Conn, boil.Infer()); err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}
	return c.Status(fiber.StatusCreated).JSON(p)
}

// Update existing project
func project_update(c *fiber.Ctx) error {
	id, err := c.ParamsInt("id")
	if err != nil || id == 0 {
		return fiber.NewError(fiber.StatusBadRequest, "invalid id")
	}
	existing, err := models.FindProject(c.Context(), db.Conn, id)
	if err == sql.ErrNoRows {
		return fiber.NewError(fiber.StatusNotFound, "project not found")
	} else if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}

	var payload struct {
		Name        *string  `json:"name"`
		Description *string  `json:"description"`
		RepoURL     *string  `json:"repo_url"`
		AvgRisk     *float64 `json:"avg_risk_score"`
		TotalVuln   *int     `json:"total_vulnerabilities"`
	}
	if err := c.BodyParser(&payload); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid payload")
	}

	if payload.Name != nil {
		existing.Name = *payload.Name
	}
	if payload.Description != nil {
		existing.Description = null.StringFromPtr(payload.Description)
	}
	if payload.RepoURL != nil {
		existing.RepoURL = null.StringFromPtr(payload.RepoURL)
	}
	if payload.AvgRisk != nil {
		d := new(decimal.Big).SetFloat64(*payload.AvgRisk)
		existing.AvgRiskScore = types.NewNullDecimal(d)
	}

	if payload.TotalVuln != nil {
		existing.TotalVulnerabilities = null.IntFrom(*payload.TotalVuln)
	}

	if _, err := existing.Update(c.Context(), db.Conn, boil.Infer()); err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}
	return c.JSON(existing)
}

// Delete a project
func project_delete(c *fiber.Ctx) error {
	id, err := c.ParamsInt("id")
	if err != nil || id == 0 {
		return fiber.NewError(fiber.StatusBadRequest, "invalid id")
	}

	p, err := models.FindProject(c.Context(), db.Conn, id)
	if err == sql.ErrNoRows {
		return fiber.NewError(fiber.StatusNotFound, "not found")
	} else if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}

	if _, err := p.Delete(c.Context(), db.Conn); err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}
	return c.JSON(fiber.Map{"message": "project deleted"})
}

type RepoInput struct {
	ID             int64    `json:"id"`
	Name           string   `json:"name"`
	FullName       string   `json:"full_name"`
	HTMLURL        string   `json:"html_url"`
	Visibility     string   `json:"visibility"`
	DefaultBranch  string   `json:"default_branch"`
	Description    *string  `json:"description"`
	Languages      []string `json:"languages"`
	OwnerID        *int     `json:"owner_id"`
	OrganizationID int      `json:"organization_id"`
}

func importGithubProjects(c *fiber.Ctx) error {
	var payload struct {
		Repos []RepoInput `json:"repos"`
	}
	if err := c.BodyParser(&payload); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid payload")
	}
	if len(payload.Repos) == 0 {
		return fiber.NewError(fiber.StatusBadRequest, "empty repo list")
	}

	var created []string

	for _, repo := range payload.Repos {
		exists, err := models.Projects(
			models.ProjectWhere.GithubRepoID.EQ(null.Int64From(repo.ID)),
		).Exists(c.Context(), db.Conn)
		if err != nil {
			return fiber.NewError(fiber.StatusInternalServerError, err.Error())
		}
		if exists {
			continue
		}

		langsJSON, _ := json.Marshal(repo.Languages)
		p := &models.Project{
			Name:                repo.Name,
			RepoURL:             null.StringFrom(repo.HTMLURL),
			SourceType:          null.StringFrom("github"),
			GithubRepoID:        null.Int64From(repo.ID),
			GithubFullName:      null.StringFrom(repo.FullName),
			GithubVisibility:    null.StringFrom(repo.Visibility),
			GithubDefaultBranch: null.StringFrom(repo.DefaultBranch),
			GithubLanguage:      null.JSONFrom(langsJSON),
			CreatedAt:           null.TimeFrom(time.Now()),
			OrganizationID:      null.IntFrom(repo.OrganizationID),
		}
		if repo.Description != nil {
			p.Description = null.StringFromPtr(repo.Description)
		}
		if repo.OwnerID != nil {
			p.OwnerID = null.IntFrom(*repo.OwnerID)
		}

		if err := p.Insert(c.Context(), db.Conn, boil.Infer()); err != nil {
			return fiber.NewError(fiber.StatusInternalServerError, err.Error())
		}
		created = append(created, repo.Name)
	}

	return c.Status(fiber.StatusCreated).JSON(fiber.Map{
		"message":           "GitHub repositories imported successfully",
		"projects_imported": len(created),
		"project_names":     created,
	})
}

func project_topLanguages(c *fiber.Ctx) error {
	rows, err := db.Conn.QueryContext(c.Context(), `
        SELECT github_language
        FROM projects
        WHERE github_language IS NOT NULL
    `)
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}
	defer rows.Close()

	languageCount := make(map[string]int)

	for rows.Next() {
		var raw sql.NullString
		if err := rows.Scan(&raw); err != nil {
			continue
		}
		if !raw.Valid {
			continue
		}

		var langs []string
		_ = json.Unmarshal([]byte(raw.String), &langs)

		for _, l := range langs {
			languageCount[l]++
		}
	}

	// Convert → array
	type Item struct {
		Name  string `json:"name"`
		Count int    `json:"count"`
	}

	list := make([]Item, 0, len(languageCount))
	for k, v := range languageCount {
		list = append(list, Item{Name: k, Count: v})
	}

	// Sort desc
	sort.Slice(list, func(i, j int) bool {
		return list[i].Count > list[j].Count
	})

	// Limit top 5
	if len(list) > 5 {
		list = list[:5]
	}

	return c.JSON(fiber.Map{
		"data": list,
	})
}
