package services

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

var supportedManifests = map[string]struct{}{
	"package-lock.json": {},
	"go.mod":            {},
	"requirements.txt":  {},
	"pom.xml":           {},
	"build.gradle":      {},
}

type SBOMResult struct {
	Project   string          `json:"project"`
	CreatedAt time.Time       `json:"created_at"`
	Format    string          `json:"format"`
	Data      json.RawMessage `json:"data"`
}

func ParseManifest(ctx context.Context, projectName, manifestName string, manifestContent []byte) (*SBOMResult, error) {
	tmpDir, err := os.MkdirTemp("", "sbom-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	tmpFile := filepath.Join(tmpDir, filepath.Base(manifestName))
	if err := os.WriteFile(tmpFile, manifestContent, 0644); err != nil {
		return nil, fmt.Errorf("failed to write temp file: %w", err)
	}

	var out bytes.Buffer
	var stderr bytes.Buffer
	var cmd *exec.Cmd

	// --- Detect ecosystem ---
	switch filepath.Base(manifestName) {
	case "pom.xml":
		// For Maven, syft should scan the directory (not the file)
		cmd = exec.CommandContext(ctx, "syft", "dir:"+tmpDir, "-o", "cyclonedx-json")
	default:
		cmd = exec.CommandContext(ctx, "syft", tmpFile, "-o", "cyclonedx-json")
	}

	cmd.Stdout = &out
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("syft failed: %w\nstderr: %s", err, stderr.String())
	}

	if out.Len() == 0 {
		return nil, fmt.Errorf("syft returned empty output (stderr: %s)", stderr.String())
	}

	return &SBOMResult{
		Project:   projectName,
		CreatedAt: time.Now().UTC(),
		Format:    "cyclonedx-json",
		Data:      out.Bytes(),
	}, nil
}

func IsSupportedManifest(filename string) bool {
	ext := filepath.Ext(filename)
	switch ext {
	case ".json", ".txt", ".xml", ".gradle", ".mod":
		base := filepath.Base(filename)
		_, ok := supportedManifests[base]
		return ok
	default:
		return false
	}
}
