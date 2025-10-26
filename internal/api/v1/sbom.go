package v1

import (
	"context"
	"io"
	"myesi-sbom-service-golang/internal/config"
	"myesi-sbom-service-golang/internal/db"
	"myesi-sbom-service-golang/internal/services"
	"net/http"

	fiber "github.com/gofiber/fiber/v2"
)

func RegisterSBOMRoutes(app *fiber.App) {
	r := app.Group("/api/sbom")
	r.Post("/upload", uploadSBOM)
	r.Get("/list", listSBOMs)
	r.Get("/:id", getSBOM)
	r.Post("/github", uploadSBOMFromGitHub)
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
func uploadSBOM(c *fiber.Ctx) error {
	projectName := c.FormValue("project_name")
	file, err := c.FormFile("file")
	if err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "file required"})
	}

	// Check for supported manifest types
	if !services.IsSupportedManifest(file.Filename) {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "unsupported file type"})
	}

	f, err := file.Open()
	if err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "cannot open file"})
	}
	defer f.Close()

	content, err := io.ReadAll(f)
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "cannot read file"})
	}

	// Parse SBOM from manifest (Syft CLI)
	sbomResult, err := services.ParseManifest(c.Context(), projectName, file.Filename, content)
	if err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	// summary can be left for later uses
	summaryJSON := []byte(`{}`)

	// Upload SBOM JSON onto S3 or fallback to DB/local storage
	url, err := services.UploadSBOMJSON(c.Context(), db.Conn, projectName, sbomResult.Data, summaryJSON)
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}

	// Write SBOM record into DB
	id, operation, err := services.UpsertSBOM(context.Background(), db.Conn, projectName, sbomResult.Data, "upload", url)
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}

	//Fetch components from SBOM JSON
	comps := services.ExtractComponents(sbomResult.Data)
	// Publish event onto Kafka
	services.PublishSBOMEvent(id, projectName, comps, operation)

	return c.JSON(fiber.Map{
		"id":           id,
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
	project := c.Query("project_name")
	limit := c.QueryInt("limit", 50)
	sboms, err := services.ListSBOM(c.Context(), db.Conn, project, limit)
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
	sbom, err := services.GetSBOM(c.Context(), db.Conn, id)
	if err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "not found"})
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

// uploadSBOMFromGitHub godoc
// @Summary Upload a manifest from a GitHub repository to generate SBOM
// @Description Fetch a manifest file from GitHub using REST API and generate a SBOM
// @Tags SBOM
// @Accept json
// @Produce json
// @Param body body v1.GitHubSBOMRequest true "GitHub repo and file info"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]interface{}
// @Failure 500 {object} map[string]interface{}
// @Router /github [post]
func uploadSBOMFromGitHub(c *fiber.Ctx) error {
	var req GitHubSBOMRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid request body"})
	}

	if !services.IsSupportedManifest(req.File) {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "unsupported file type"})
	}

	if config.LoadConfig().Token == "" {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "GITHUB_TOKEN not set"})
	}

	content, err := services.FetchManifestFromGitHub(c.Context(), req.Owner, req.Repo, req.File, req.Branch, config.LoadConfig().Token)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	sbomResult, err := services.ParseManifest(c.Context(), req.Project, req.File, content)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	summaryJSON := []byte("{}")
	url, err := services.UploadSBOMJSON(c.Context(), db.Conn, req.Project, sbomResult.Data, summaryJSON)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}

	id, operation, err := services.UpsertSBOM(c.Context(), db.Conn, req.Project, sbomResult.Data, "github", url)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}

	//Fetch components from SBOM JSON
	comps := services.ExtractComponents(sbomResult.Data)

	// Publish event onto Kafka
	services.PublishSBOMEvent(id, req.Project, comps, operation)

	return c.JSON(fiber.Map{
		"id":           id,
		"project_name": req.Project,
		"object_url":   url,
		"message":      "SBOM generated from GitHub manifest and queued for vulnerability scan",
	})
}
