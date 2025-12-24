package services

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestIsSupportedManifest(t *testing.T) {
	require.True(t, IsSupportedManifest("go.mod"))
	require.True(t, IsSupportedManifest("package-lock.json"))
	require.True(t, IsSupportedManifest("requirements.txt"))
	require.True(t, IsSupportedManifest("pom.xml"))
	require.True(t, IsSupportedManifest("build.gradle"))

	require.False(t, IsSupportedManifest("abc.json"))    // ext ok but basename not allowed
	require.False(t, IsSupportedManifest("deps.yaml"))   // ext not allowed
	require.False(t, IsSupportedManifest("random.lock")) // ext not allowed
}

func TestParseSBOMSummary_InvalidJSON(t *testing.T) {
	_, err := ParseSBOMSummary([]byte("{bad json"))
	require.Error(t, err)
}

func TestParseSBOMSummary_ExtractsBasics(t *testing.T) {
	sbom := map[string]any{
		"components": []any{
			map[string]any{
				"name":    "a",
				"version": "1",
				"properties": []any{
					map[string]any{"name": "syft:package:language", "value": "go"},
				},
				"licenses": []any{
					map[string]any{"license": map[string]any{"id": "MIT"}},
				},
			},
			map[string]any{
				"name":    "b",
				"version": "2",
				"properties": []any{
					map[string]any{"name": "syft:package:language", "value": "python"},
				},
				"licenses": []any{
					map[string]any{"license": map[string]any{"id": "Apache-2.0"}},
				},
			},
		},
		"metadata": map[string]any{
			"tools": map[string]any{
				"components": []any{
					map[string]any{"name": "syft", "version": "1.0.0"},
				},
			},
			"timestamp": "2025-01-01T00:00:00Z",
		},
	}
	raw, _ := json.Marshal(sbom)

	s, err := ParseSBOMSummary(raw)
	require.NoError(t, err)
	require.Equal(t, 2, s.TotalComponents)
	require.ElementsMatch(t, []string{"go", "python"}, s.Languages)
	require.ElementsMatch(t, []string{"MIT", "Apache-2.0"}, s.Licenses)
	require.ElementsMatch(t, []string{"syft@1.0.0"}, s.Tools)
	require.Equal(t, "2025-01-01T00:00:00Z", s.GeneratedAt)
}

func TestExtractComponents_PurlWins(t *testing.T) {
	sbom := map[string]any{
		"components": []any{
			map[string]any{
				"name":    "requests",
				"version": "2.0.0",
				"purl":    "pkg:pypi/requests@2.0.0",
			},
			map[string]any{
				"name":    "lodash",
				"version": "4.0.0",
				"purl":    "pkg:npm/lodash@4.0.0",
			},
		},
	}
	raw, _ := json.Marshal(sbom)

	comps := ExtractComponents(raw)
	require.Len(t, comps, 2)
	require.Equal(t, "pypi", comps[0]["type"])
	require.Equal(t, "npm", comps[1]["type"])
}

func TestBuildSBOMFromFindings(t *testing.T) {
	findings := []map[string]any{
		{"check_id": "G101", "path": "a.go", "severity": "HIGH", "message": "bad"},
	}
	in := make([]map[string]interface{}, 0, len(findings))
	for _, f := range findings {
		ff := map[string]interface{}{}
		for k, v := range f {
			ff[k] = v
		}
		in = append(in, ff)
	}

	sbom := BuildSBOMFromFindings(in)
	require.Equal(t, "CycloneDX", sbom["bomFormat"])
	require.Equal(t, "1.4", sbom["specVersion"])

	comps := sbom["components"].([]map[string]interface{})
	require.Len(t, comps, 1)
	require.Equal(t, "G101", comps[0]["name"])
}
