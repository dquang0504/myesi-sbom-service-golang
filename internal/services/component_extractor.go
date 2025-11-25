package services

import (
	"encoding/json"
	"log"
	"strings"
)

func ExtractComponents(sbomJSON []byte) []map[string]string {
	var sbom map[string]interface{}
	if err := json.Unmarshal(sbomJSON, &sbom); err != nil {
		log.Println("cannot unmarshal SBOM JSON:", err)
		return nil
	}

	comps := []map[string]string{}

	// --- 1. CycloneDX standard ---
	if components, ok := sbom["components"].([]interface{}); ok {
		for _, c := range components {
			comp, ok := c.(map[string]interface{})
			if !ok {
				continue
			}

			name, _ := comp["name"].(string)
			version, _ := comp["version"].(string)
			if name == "" || version == "" {
				continue
			}

			// ============================
			// 1) Detect ecosystem properly
			// ============================
			eco := detectEcosystem(comp)

			comps = append(comps, map[string]string{
				"name":    name,
				"version": version,
				"type":    eco,
			})
		}
	}

	// --- 2. SPDX ---
	if spdxPkgs, ok := sbom["packages"].([]interface{}); ok {
		for _, p := range spdxPkgs {
			pkg, ok := p.(map[string]interface{})
			if !ok {
				continue
			}
			name, _ := pkg["name"].(string)
			version, _ := pkg["versionInfo"].(string)
			if name == "" || version == "" {
				continue
			}
			comps = append(comps, map[string]string{
				"name":    name,
				"version": version,
				"type":    "unknown",
			})
		}
	}

	// --- 3. Syft fallback ---
	if artifacts, ok := sbom["artifacts"].([]interface{}); ok {
		for _, a := range artifacts {
			art, ok := a.(map[string]interface{})
			if !ok {
				continue
			}
			name, _ := art["name"].(string)
			version, _ := art["version"].(string)
			if name == "" || version == "" {
				continue
			}
			eco := detectEcosystem(art)
			comps = append(comps, map[string]string{
				"name":    name,
				"version": version,
				"type":    eco,
			})
		}
	}

	return comps
}

// ===========================================================
// BEST-PRACTICE ECOSYSTEM DETECTION (CycloneDX + Syft)
// ===========================================================
func detectEcosystem(comp map[string]interface{}) string {

	// 1) purl ALWAYS wins (CycloneDX best practice)
	if purl, ok := comp["purl"].(string); ok && purl != "" {
		p := strings.ToLower(purl)
		switch {
		case strings.HasPrefix(p, "pkg:pypi/"):
			return "pypi"
		case strings.HasPrefix(p, "pkg:npm/"):
			return "npm"
		case strings.HasPrefix(p, "pkg:maven/"):
			return "maven"
		case strings.HasPrefix(p, "pkg:golang/"), strings.HasPrefix(p, "pkg:go/"):
			return "golang"
		case strings.HasPrefix(p, "pkg:composer/"):
			return "composer"
		case strings.HasPrefix(p, "pkg:nuget/"):
			return "nuget"
		}
	}

	// 2) syft:package:language (very reliable)
	if props, ok := comp["properties"].([]interface{}); ok {
		for _, p := range props {
			prop, _ := p.(map[string]interface{})
			if prop["name"] == "syft:package:language" {
				v := strings.ToLower(prop["value"].(string))
				switch v {
				case "python":
					return "pypi"
				case "javascript":
					return "npm"
				case "go":
					return "golang"
				case "java":
					return "maven"
				}
			}
		}
	}

	// 3) syft:package:type
	if props, ok := comp["properties"].([]interface{}); ok {
		for _, p := range props {
			prop, _ := p.(map[string]interface{})
			if prop["name"] == "syft:package:type" {
				v := strings.ToLower(prop["value"].(string))
				switch v {
				case "python":
					return "pypi"
				case "npm":
					return "npm"
				case "golang":
					return "golang"
				case "maven":
					return "maven"
				}
			}
		}
	}

	return "unknown" // ← KHÔNG fallback "npm" nữa
}
