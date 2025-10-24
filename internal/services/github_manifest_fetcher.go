package services

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

type githubContentResponse struct{
	Name string `json:"name"`
	Path string `json:"path"`
	Content string `json:"content"`
	Encoding string `json:"encoding"`
}

//FetchManifestFromGitHub fetches a single file content from GitHub (e.g go.mod)
func FetchManifestFromGitHub(ctx context.Context, owner, repo, path, branch, token string) ([]byte, error){
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/contents/%s?ref=%s", owner, repo, path, branch)

	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	req.Header.Set("Authorization", "token " + token)
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil{
		return nil, fmt.Errorf("github request error: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200{
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("github API error %d: %s", resp.StatusCode, string(body))
	}

	var ghResp githubContentResponse
	if err := json.NewDecoder(resp.Body).Decode(&ghResp); err != nil{
		return nil, fmt.Errorf("failed to decode github response: %w", err)
	}

	if ghResp.Encoding != "base64"{
		return nil, fmt.Errorf("unexpected encoding: %s", ghResp.Encoding)
	}

	data, err := base64.StdEncoding.DecodeString(ghResp.Content)
	if err != nil{
		return nil, fmt.Errorf("failed to decode base64 content: %w", err)
	}
	return data, nil
} 