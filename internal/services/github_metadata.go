package services

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"
)

type GitHubRepoMetadata struct {
	RepoID         int64
	FullName       string
	Visibility     string
	DefaultBranch  string
	Languages      []string
	Stargazers     int
	Forks          int
	IsFork         bool
	LastSyncedTime time.Time
}

var httpClient = &http.Client{
	Timeout: 10 * time.Second,
}

// FetchGitHubRepoMetadata pulls repository information (basic details + languages)
// from the GitHub REST API. It accepts typical HTTPS or SSH repository URLs.
func FetchGitHubRepoMetadata(ctx context.Context, repoURL string) (*GitHubRepoMetadata, error) {
	slug, err := normalizeRepoSlug(repoURL)
	if err != nil {
		return nil, err
	}

	repoEndpoint := fmt.Sprintf("https://api.github.com/repos/%s", slug)
	repoRespBody, err := doGitHubRequest(ctx, repoEndpoint)
	if err != nil {
		return nil, err
	}
	defer repoRespBody.Close()

	var repoPayload struct {
		ID            int64  `json:"id"`
		FullName      string `json:"full_name"`
		Visibility    string `json:"visibility"`
		DefaultBranch string `json:"default_branch"`
		Private       bool   `json:"private"`
		Fork          bool   `json:"fork"`
		Stargazers    int    `json:"stargazers_count"`
		Forks         int    `json:"forks_count"`
	}
	if err := json.NewDecoder(repoRespBody).Decode(&repoPayload); err != nil {
		return nil, fmt.Errorf("decode github repo payload: %w", err)
	}

	languageEndpoint := fmt.Sprintf("https://api.github.com/repos/%s/languages", slug)
	langRespBody, err := doGitHubRequest(ctx, languageEndpoint)
	languages := []string{}
	if err == nil {
		defer langRespBody.Close()
		var langMap map[string]int
		if err := json.NewDecoder(langRespBody).Decode(&langMap); err == nil {
			for lang := range langMap {
				languages = append(languages, lang)
			}
			sort.Strings(languages)
		}
	}

	visibility := repoPayload.Visibility
	if visibility == "" {
		if repoPayload.Private {
			visibility = "private"
		} else {
			visibility = "public"
		}
	}

	return &GitHubRepoMetadata{
		RepoID:         repoPayload.ID,
		FullName:       repoPayload.FullName,
		Visibility:     visibility,
		DefaultBranch:  repoPayload.DefaultBranch,
		Languages:      languages,
		Stargazers:     repoPayload.Stargazers,
		Forks:          repoPayload.Forks,
		IsFork:         repoPayload.Fork,
		LastSyncedTime: time.Now().UTC(),
	}, nil
}

func doGitHubRequest(ctx context.Context, endpoint string) (io.ReadCloser, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	if token := strings.TrimSpace(os.Getenv("GITHUB_FALLBACK_TOKEN")); token != "" {
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= http.StatusBadRequest {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return nil, fmt.Errorf("github api %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return resp.Body, nil
}

func normalizeRepoSlug(repoURL string) (string, error) {
	trimmed := strings.TrimSpace(repoURL)
	if trimmed == "" {
		return "", fmt.Errorf("empty repo url")
	}

	trimmed = strings.TrimSuffix(trimmed, ".git")

	if strings.HasPrefix(trimmed, "git@") {
		// git@github.com:owner/repo
		parts := strings.SplitN(trimmed, ":", 2)
		if len(parts) != 2 {
			return "", fmt.Errorf("invalid git ssh url")
		}
		path := strings.TrimSuffix(parts[1], ".git")
		path = strings.Trim(path, "/")
		split := strings.Split(path, "/")
		if len(split) < 2 {
			return "", fmt.Errorf("invalid repo path in ssh url")
		}
		return fmt.Sprintf("%s/%s", split[0], split[1]), nil
	}

	u, err := url.Parse(trimmed)
	if err != nil {
		return "", fmt.Errorf("invalid repo url: %w", err)
	}
	host := strings.ToLower(strings.TrimSpace(u.Host))
	if host != "github.com" && host != "www.github.com" {
		return "", fmt.Errorf("unsupported host (expected github.com)")
	}
	path := strings.Trim(u.Path, "/")
	parts := strings.Split(path, "/")
	if len(parts) < 2 {
		return "", fmt.Errorf("invalid repo path")
	}
	return fmt.Sprintf("%s/%s", parts[0], parts[1]), nil
}
