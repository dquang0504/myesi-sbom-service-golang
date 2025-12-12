package v1

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"myesi-sbom-service-golang/internal/db"
	"myesi-sbom-service-golang/internal/services"
	"net/http"
	"strings"
	"time"

	fiber "github.com/gofiber/fiber/v2"
)

func RegisterSBOMRoutes(r fiber.Router) {
	r.Post("/upload", uploadSBOM)
	r.Get("/list", listSBOMs)
	r.Get("/recent", recentSBOMs)
	r.Get("/analytics", sbomAnalytics)
	r.Get("/:id", getSBOM)
}

// uploadSBOM godoc
// @Summary Upload a manifest file to generate SBOM
// @Description Upload a manifest file and generate an SBOM
// @Tags SBOM
// @Accept multipart/form-data
// @Produce json
// @Param project_name formData string true "Project Name"
// @Param file formData file true "Manifest file"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]interface{}
// @Router /upload [post]
// uploadSBOM godoc
// @Summary Upload a manifest file to generate SBOM
// @Description Upload a manifest file and generate an SBOM
// @Tags SBOM
// @Accept multipart/form-data
// @Produce json
// @Param project_name formData string true "Project Name"
// @Param file formData file true "Manifest file"
func uploadSBOM(c *fiber.Ctx) error {
	projectName := c.FormValue("project_name")
	file, err := c.FormFile("file")
	if err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "file required"})
	}

	orgID, err := requireOrgID(c)
	if err != nil {
		return err
	}

	// ---------------------------------------------------------
	// 1. Lấy project_id
	// ---------------------------------------------------------
	projectID, err := ensureProjectAccessible(c.Context(), projectName, orgID)
	if err != nil {
		return err
	}

	// ---------------------------------------------------------
	// 3. Check quota (consume trước, nhưng revert nếu fail)
	// ---------------------------------------------------------
	var allowed bool
	var msg string
	var periodEnd sql.NullTime

	row := db.Conn.QueryRowContext(
		c.Context(),
		"SELECT allowed, message, next_reset FROM check_and_consume_usage($1,$2,$3)",
		orgID, "sbom_upload", 1,
	)

	if err := row.Scan(&allowed, &msg, &periodEnd); err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "usage check failed: " + err.Error()})
	}

	if !allowed {
		return c.Status(429).JSON(fiber.Map{"error": msg})
	}

	// ---------------------------------------------------------
	// HELPER FUNCTION: revert usage safely
	// ---------------------------------------------------------
	revert := func() {
		_, _ = db.Conn.ExecContext(
			c.Context(),
			"SELECT revert_usage($1,$2,$3)",
			orgID, "sbom_upload", 1,
		)
	}

	// ---------------------------------------------------------
	// 4. Validate manifest type
	// ---------------------------------------------------------
	manifestName := file.Filename
	if !services.IsSupportedManifest(manifestName) {
		revert()
		return c.Status(400).JSON(fiber.Map{"error": "unsupported file type"})
	}

	// ---------------------------------------------------------
	// 5. Read file
	// ---------------------------------------------------------
	f, err := file.Open()
	if err != nil {
		revert()
		return c.Status(400).JSON(fiber.Map{"error": "cannot open file"})
	}
	defer f.Close()

	content, err := io.ReadAll(f)
	if err != nil {
		revert()
		return c.Status(500).JSON(fiber.Map{"error": "cannot read file"})
	}

	// ---------------------------------------------------------
	// 6. Parse SBOM using syft
	// ---------------------------------------------------------
	sbomResult, err := services.ParseManifest(
		c.Context(), projectName, manifestName, content,
	)
	if err != nil {
		revert()
		return c.Status(400).JSON(fiber.Map{"error": err.Error()})
	}

	summaryJSON := []byte(`{}`)

	// ---------------------------------------------------------
	// 7. Upload JSON to S3 or DB
	// ---------------------------------------------------------
	url, err := services.UploadSBOMJSON(
		c.Context(), db.Conn,
		projectID, projectName, manifestName,
		sbomResult.Data, summaryJSON,
	)
	if err != nil {
		revert()
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}

	// ---------------------------------------------------------
	// 8. Insert/update SBOM in database
	// ---------------------------------------------------------
	id, _, err := services.UpsertSBOM(
		context.Background(), db.Conn,
		projectID, projectName, manifestName,
		sbomResult.Data, "manual", url,
	)

	if err != nil {
		revert()
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}

	// ---------------------------------------------------------
	// 9. Extract components + publish event
	// ---------------------------------------------------------
	components := services.ExtractComponents(sbomResult.Data)
	services.PublishSBOMEvent(id, projectName, projectID, orgID, components, "manual")
	services.PublishManualSBOMSummary(orgID, projectName, len(components), 0, "completed")

	return c.JSON(fiber.Map{
		"id":           id,
		"project_id":   projectID,
		"project_name": projectName,
		"object_url":   url,
		"message":      "SBOM uploaded and queued for vulnerability scan",
	})
}

// listSBOMs godoc
// @Summary List SBOMs
// @Description Get list of SBOMs filtered by project name
// @Tags SBOM
// @Accept json
// @Produce json
// @Param project_name query string false "Project Name"
// @Param limit query int false "Limit"
// @Success 200 {array} map[string]interface{}
// @Failure 500 {object} map[string]interface{}
// @Router /list [get]
func listSBOMs(c *fiber.Ctx) error {
	orgID, err := requireOrgID(c)
	if err != nil {
		return err
	}
	project := c.Query("project_name")
	limit := c.QueryInt("limit", 50)
	sboms, err := services.ListSBOM(c.Context(), db.Conn, project, limit, orgID)
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(sboms)
}

// getSBOM godoc
// @Summary Get SBOM by ID
// @Description Retrieve a single SBOM by its ID
// @Tags SBOM
// @Accept json
// @Produce json
// @Param id path string true "SBOM ID"
// @Success 200 {object} map[string]interface{}
// @Failure 404 {object} map[string]interface{}
// @Router /{id} [get]
func getSBOM(c *fiber.Ctx) error {
	id := c.Params("id")
	orgID, err := requireOrgID(c)
	if err != nil {
		return err
	}
	if err := ensureSBOMAccessible(c.Context(), id, orgID); err != nil {
		return err
	}
	sbom, err := services.GetSBOM(c.Context(), db.Conn, id)
	if err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "not found ád"})
	}
	return c.JSON(sbom)
}

type GitHubSBOMRequest struct {
	Owner   string `json:"owner"`
	Repo    string `json:"repo"`
	Branch  string `json:"branch"`
	File    string `json:"file"` //e.g package.json, go.mod, requirements.txt...
	Project string `json:"project_name"`
}

// recentSBOMs godoc
// @Summary Recent SBOM uploads
// @Description Get recent SBOM uploads with optional project filter
// @Tags SBOM
// @Accept json
// @Produce json
// @Param project_name query string false "Project Name"
// @Param source query string false "Source (manual|auto-code-scan)"
// @Param q query string false "Search (project or manifest)"
// @Param page query int false "Page (default 1)"
// @Param page_size query int false "Page size (max 100, default 10)"
// @Success 200 {object} map[string]interface{}
// @Failure 500 {object} map[string]interface{}
// @Router /recent [get]
func recentSBOMs(c *fiber.Ctx) error {
	orgID, err := requireOrgID(c)
	if err != nil {
		return err
	}
	project := c.Query("project_name")
	source := strings.ToLower(strings.TrimSpace(c.Query("source")))
	search := strings.TrimSpace(c.Query("q"))
	page := c.QueryInt("page", 1)
	if page < 1 {
		page = 1
	}
	pageSize := c.QueryInt("page_size", 10)
	if pageSize <= 0 || pageSize > 100 {
		pageSize = 10
	}
	offset := (page - 1) * pageSize

	var (
		whereParts []string
		args       []interface{}
	)
	whereParts = append(whereParts, orgProjectFilterClause())
	args = append(args, orgID)
	nextParam := func() string {
		return fmt.Sprintf("$%d", len(args)+1)
	}

	if project != "" {
		placeholder := nextParam()
		whereParts = append(whereParts, fmt.Sprintf("s.project_name = %s", placeholder))
		args = append(args, project)
	}
	if source != "" && source != "all" {
		placeholder := nextParam()
		whereParts = append(whereParts, fmt.Sprintf("LOWER(s.source) = %s", placeholder))
		args = append(args, source)
	}
	if search != "" {
		placeholder := nextParam()
		whereParts = append(whereParts, fmt.Sprintf("(s.manifest_name ILIKE %s OR s.project_name ILIKE %s)", placeholder, placeholder))
		args = append(args, "%"+search+"%")
	}

	whereClause := strings.Join(whereParts, " AND ")

	countQuery := fmt.Sprintf(`SELECT COUNT(*) FROM sboms s WHERE %s`, whereClause)
	var total int
	if err := db.Conn.QueryRowContext(c.Context(), countQuery, args...).Scan(&total); err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}

	argsWithPaging := append([]interface{}{}, args...)
	argsWithPaging = append(argsWithPaging, pageSize, offset)
	limitPlaceholder := fmt.Sprintf("$%d", len(args)+1)
	offsetPlaceholder := fmt.Sprintf("$%d", len(args)+2)
	listQuery := fmt.Sprintf(`
		SELECT id, project_name, manifest_name, object_url, created_at, source,
		       COALESCE(jsonb_array_length(sbom->'components'), 0) AS findings
		FROM sboms s
		WHERE %s
		ORDER BY created_at DESC
		LIMIT %s OFFSET %s
	`, whereClause, limitPlaceholder, offsetPlaceholder)

	rows, err := db.Conn.QueryContext(c.Context(), listQuery, argsWithPaging...)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}
	defer rows.Close()

	type SBOMItem struct {
		ID           string `json:"id"`
		ProjectName  string `json:"project_name"`
		ManifestName string `json:"manifest_name"`
		ObjectURL    string `json:"object_url"`
		CreatedAt    string `json:"created_at"`
		Source       string `json:"source"`
		Findings     int    `json:"findings"`
	}

	var list []SBOMItem
	for rows.Next() {
		var (
			id, projectName, sourceVal string
			manifestName, objectURL    sql.NullString
			createdAt                  time.Time
			findings                   int
		)
		if err := rows.Scan(&id, &projectName, &manifestName, &objectURL, &createdAt, &sourceVal, &findings); err != nil {
			return c.Status(500).JSON(fiber.Map{"error": err.Error()})
		}

		list = append(list, SBOMItem{
			ID:           id,
			ProjectName:  projectName,
			ManifestName: manifestName.String, // nếu null -> ""
			ObjectURL:    objectURL.String,
			CreatedAt:    createdAt.Format(time.RFC3339),
			Source:       sourceVal,
			Findings:     findings,
		})
	}

	return c.JSON(fiber.Map{
		"data":      list,
		"page":      page,
		"page_size": pageSize,
		"total":     total,
	})
}

func sbomAnalytics(c *fiber.Ctx) error {
	orgID, err := requireOrgID(c)
	if err != nil {
		return err
	}
	ctx := c.Context()
	baseClause := orgProjectFilterClause()

	// 1) scannedToday
	var scannedToday int
	err = db.Conn.QueryRowContext(
		ctx,
		`SELECT COUNT(*) FROM sboms s WHERE `+baseClause+` AND s.created_at::date = CURRENT_DATE`,
		orgID,
	).Scan(&scannedToday)

	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}

	// 2) sbomTrend (last 14 days)
	rows, err := db.Conn.QueryContext(ctx, `
        SELECT
            s.created_at::date AS date,
            COUNT(*) AS scanned,
            COUNT(*) FILTER (WHERE s.source = 'upload') AS uploaded
        FROM sboms s
        WHERE `+baseClause+`
          AND s.created_at >= CURRENT_DATE - INTERVAL '14 days'
        GROUP BY s.created_at::date
        ORDER BY date ASC
    `, orgID)

	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}
	defer rows.Close()

	type TrendItem struct {
		Date     string `json:"date"`
		Scanned  int    `json:"scanned"`
		Uploaded int    `json:"uploaded"`
	}

	trends := []TrendItem{}
	for rows.Next() {
		var rawDate time.Time
		var scanned int
		var uploaded int

		if err := rows.Scan(&rawDate, &scanned, &uploaded); err != nil {
			return c.Status(500).JSON(fiber.Map{"error": err.Error()})
		}

		trends = append(trends, TrendItem{
			Date:     rawDate.Format("2006-01-02"),
			Scanned:  scanned,
			Uploaded: uploaded,
		})
	}

	return c.JSON(fiber.Map{
		"scannedToday": scannedToday,
		"sbomTrend":    trends,
	})
}
