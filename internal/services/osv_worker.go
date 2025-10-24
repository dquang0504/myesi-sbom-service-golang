package services

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
	"myesi-sbom-service-golang/internal/db"
	"net/http"
)

const OSV_URL = "https://api.osv.dev/v1/querybatch"

func EnqueueOSVScan(sbomID string){
	go scanVulnerabilities(sbomID)
}

func scanVulnerabilities(sbomID string) {
	// Load SBOM from DB
	sbom, err := GetSBOM(context.Background(), db.Conn, sbomID)
	if err != nil{
		log.Println("OSV scan failed:", err)
		return
	}
	var comps []map[string]string
	json.Unmarshal(sbom.Sbom, &comps)

	queries := []map[string]map[string]string{}
	for _, c := range comps{
		queries = append(queries, map[string]map[string]string{"package": {"name": c["name"], "version": c["version"]}})
	}
	payload, _ := json.Marshal(map[string]interface{}{"queries": queries})

	resp, err := http.Post(OSV_URL, "application/json", bytes.NewReader(payload))
	if err != nil{
		log.Println("OSV API error: ", err)
		return
	}
	defer resp.Body.Close()
	log.Printf("[OSV] Scan result for %s status: %d", sbomID, resp.StatusCode)
}