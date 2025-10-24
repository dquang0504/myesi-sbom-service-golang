package services

import (
	"encoding/json"
	"time"
)

type SbomSummary struct {
	TotalComponents int      `json:"total_components"`
	Languages       []string `json:"languages,omitempty"`
	Licenses        []string `json:"licenses,omitempty"`
	Tools           []string `json:"tools,omitempty"`
	GeneratedAt     string   `json:"generated_at,omitempty"`
}

// ParseSBOMSummary reads CycloneDX-style SBOM JSON and extracts summary info.
func ParseSBOMSummary(sbomData []byte) (*SbomSummary, error) {
	var sbom map[string]interface{}
	if err := json.Unmarshal(sbomData, &sbom); err != nil {
		return nil, err
	}

	summary := &SbomSummary{}

	// --- 1. Count components ---
	if comps, ok := sbom["components"].([]interface{}); ok {
		summary.TotalComponents = len(comps)

		langSet := map[string]struct{}{}
		licenseSet := map[string]struct{}{}

		for _, c := range comps {
			comp, ok := c.(map[string]interface{})
			if !ok {
				continue
			}

			// --- Language ---
			if props, ok := comp["properties"].([]interface{}); ok {
				for _, p := range props {
					prop := p.(map[string]interface{})
					if prop["name"] == "syft:package:language" {
						lang := prop["value"].(string)
						langSet[lang] = struct{}{}
					}
				}
			}

			// --- Licenses ---
			if licenses, ok := comp["licenses"].([]interface{}); ok {
				for _, l := range licenses {
					licObj := l.(map[string]interface{})
					if lic, ok := licObj["license"].(map[string]interface{}); ok {
						if id, ok := lic["id"].(string); ok {
							licenseSet[id] = struct{}{}
						}
					}
				}
			}
		}

		// Convert map to slice
		for k := range langSet {
			summary.Languages = append(summary.Languages, k)
		}
		for k := range licenseSet {
			summary.Licenses = append(summary.Licenses, k)
		}
	}

	// --- 2. Extract tools ---
	if meta, ok := sbom["metadata"].(map[string]interface{}); ok {
		if tools, ok := meta["tools"].(map[string]interface{}); ok {
			if comps, ok := tools["components"].([]interface{}); ok {
				for _, c := range comps {
					comp := c.(map[string]interface{})
					name := comp["name"].(string)
					version := comp["version"].(string)
					summary.Tools = append(summary.Tools, name+"@"+version)
				}
			}
		}
		if ts, ok := meta["timestamp"].(string); ok {
			summary.GeneratedAt = ts
		}
	}

	// --- fallback timestamp ---
	if summary.GeneratedAt == "" {
		summary.GeneratedAt = time.Now().UTC().Format(time.RFC3339)
	}

	return summary, nil
}