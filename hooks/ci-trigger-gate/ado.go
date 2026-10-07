package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------
// Azure DevOps Git URL parsing
// ---------------------------------------------------------------------------

// adoRepo identifies a Git repository in Azure DevOps.
type adoRepo struct {
	Org     string
	Project string
	Repo    string
}

// parseADORepoURL parses an Azure DevOps Git URL. Supported forms:
//
//	https://dev.azure.com/{org}/{project}/_git/{repo}
//	https://{user}@dev.azure.com/{org}/{project}/_git/{repo}
//	https://{org}.visualstudio.com/{project}/_git/{repo}
//	https://{org}.visualstudio.com/DefaultCollection/{project}/_git/{repo}
//	git@ssh.dev.azure.com:v3/{org}/{project}/{repo}
//
// It returns false for all other URLs.
func parseADORepoURL(raw string) (adoRepo, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return adoRepo{}, false
	}

	if rest, ok := strings.CutPrefix(raw, "git@ssh.dev.azure.com:v3/"); ok {
		parts := strings.Split(strings.Trim(rest, "/"), "/")
		if len(parts) != 3 {
			return adoRepo{}, false
		}
		return cleanADORepo(parts[0], parts[1], parts[2])
	}

	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") {
		return adoRepo{}, false
	}
	host := strings.ToLower(u.Hostname())
	segs := strings.Split(strings.Trim(u.Path, "/"), "/")

	var org string
	switch {
	case host == "dev.azure.com":
		if len(segs) < 1 {
			return adoRepo{}, false
		}
		org, segs = segs[0], segs[1:]
	case strings.HasSuffix(host, ".visualstudio.com"):
		org = strings.TrimSuffix(host, ".visualstudio.com")
		if len(segs) > 0 && strings.EqualFold(segs[0], "DefaultCollection") {
			segs = segs[1:]
		}
	default:
		return adoRepo{}, false
	}

	// Expect {project}/_git/{repo}. Ignore any path after the repo name.
	if len(segs) < 3 || segs[1] != "_git" {
		return adoRepo{}, false
	}
	return cleanADORepo(org, segs[0], segs[2])
}

func cleanADORepo(org, project, repo string) (adoRepo, bool) {
	repo = strings.TrimSuffix(repo, ".git")
	if org == "" || project == "" || repo == "" {
		return adoRepo{}, false
	}
	return adoRepo{Org: org, Project: project, Repo: repo}, true
}

// ---------------------------------------------------------------------------
// ADO CI provider
// ---------------------------------------------------------------------------

// buildInfo is the subset of an Azure DevOps build that the gate uses.
type buildInfo struct {
	TemplateParameters map[string]any `json:"templateParameters"`
	Status             string         `json:"status"`
	Result             string         `json:"result"`
	Links              struct {
		Web struct {
			Href string `json:"href"`
		} `json:"web"`
	} `json:"_links"`
	ID int `json:"id"`
}

func (b *buildInfo) webURL() string {
	return b.Links.Web.Href
}

// ciProvider talks to Azure DevOps. Abstracted for testing.
type ciProvider interface {
	// branchExists reports whether refs/heads/{branch} exists in repo.
	branchExists(ctx context.Context, repo adoRepo, branch string) (bool, error)
	// findRunningBuild returns an unfinished build of the pipeline whose
	// imageTag template parameter equals imageTag, or nil.
	findRunningBuild(ctx context.Context, pipelineID int, imageTag string) (*buildInfo, error)
	// queueBuild queues a new build of the pipeline.
	queueBuild(ctx context.Context, pipelineID int, branch, imageTag string) (*buildInfo, error)
	// getBuild returns the current state of a build.
	getBuild(ctx context.Context, buildID int) (*buildInfo, error)
	// ping gets an Azure DevOps token. It is used by /readyz.
	ping(ctx context.Context) error
}

type adoClient struct {
	entra        *entraTokenSource
	client       *http.Client
	baseURL      string // https://dev.azure.com; tests point it at a fake server
	org          string
	project      string
	mode         string // authWorkloadIdentity or authPAT
	pat          string
	sourceBranch string // pipeline repo ref for queued builds
}

func newADOClient(org, project, mode, pat, sourceBranch string, entra *entraTokenSource) *adoClient {
	return &adoClient{
		baseURL:      "https://dev.azure.com",
		org:          org,
		project:      project,
		mode:         mode,
		pat:          pat,
		sourceBranch: sourceBranch,
		entra:        entra,
		client:       &http.Client{Timeout: 30 * time.Second},
	}
}

func (a *adoClient) authHeader(ctx context.Context) (string, error) {
	switch a.mode {
	case authWorkloadIdentity:
		if a.entra == nil {
			return "", errors.New("workload identity credential is not configured")
		}
		tok, err := a.entra.token(ctx, adoScope)
		if err != nil {
			return "", fmt.Errorf("entra token for Azure DevOps: %w", err)
		}
		return "Bearer " + tok, nil
	case authPAT:
		if a.pat == "" {
			return "", errors.New("ADO_PAT is not set")
		}
		return basicAuth("", a.pat), nil
	default:
		return "", errors.New("Azure DevOps authentication is not configured")
	}
}

func (a *adoClient) ping(ctx context.Context) error {
	if a.org == "" || a.project == "" {
		return errors.New("ADO_ORG or ADO_PROJECT is not set")
	}
	_, err := a.authHeader(ctx)
	return err
}

func (a *adoClient) buildsURL() string {
	return fmt.Sprintf("%s/%s/%s/_apis/build/builds", a.baseURL, url.PathEscape(a.org), url.PathEscape(a.project))
}

// doJSON sends a request and decodes a JSON response into out.
func (a *adoClient) doJSON(ctx context.Context, method, u string, in, out any) error {
	auth, err := a.authHeader(ctx)
	if err != nil {
		return err
	}
	var body io.Reader
	if in != nil {
		payload, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(payload)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", auth)
	req.Header.Set("Accept", "application/json")
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := a.client.Do(req)
	if err != nil {
		return fmt.Errorf("ADO %s: %w", method, err)
	}
	defer resp.Body.Close()
	// ADO sends 203 with a sign-in page when the credentials are not valid.
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		if resp.StatusCode == http.StatusNonAuthoritativeInfo {
			msg = []byte("check the Azure DevOps credentials")
		}
		return fmt.Errorf("ADO %s %s returned status %d: %s", method, redactQuery(u), resp.StatusCode, strings.TrimSpace(string(msg)))
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(out); err != nil {
		return fmt.Errorf("decode ADO response: %w", err)
	}
	return nil
}

func (a *adoClient) branchExists(ctx context.Context, repo adoRepo, branch string) (bool, error) {
	q := url.Values{
		"filter":      {"heads/" + branch},
		"api-version": {"7.1"},
	}
	u := fmt.Sprintf("%s/%s/%s/_apis/git/repositories/%s/refs?%s", a.baseURL,
		url.PathEscape(repo.Org), url.PathEscape(repo.Project), url.PathEscape(repo.Repo), q.Encode())

	var result struct {
		Value []struct {
			Name string `json:"name"`
		} `json:"value"`
	}
	if err := a.doJSON(ctx, http.MethodGet, u, nil, &result); err != nil {
		return false, err
	}
	// The filter is a prefix match. Only an exact name counts.
	want := "refs/heads/" + branch
	for _, ref := range result.Value {
		if ref.Name == want {
			return true, nil
		}
	}
	return false, nil
}

func (a *adoClient) findRunningBuild(ctx context.Context, pipelineID int, imageTag string) (*buildInfo, error) {
	q := url.Values{
		"definitions":  {strconv.Itoa(pipelineID)},
		"statusFilter": {"inProgress,notStarted"},
		"api-version":  {"7.1"},
	}
	var result struct {
		Value []buildInfo `json:"value"`
	}
	if err := a.doJSON(ctx, http.MethodGet, a.buildsURL()+"?"+q.Encode(), nil, &result); err != nil {
		return nil, err
	}
	for i := range result.Value {
		b := &result.Value[i]
		if b.Status == "completed" {
			continue
		}
		if b.TemplateParameters == nil {
			// The list can omit template parameters. Read the build itself.
			full, err := a.getBuild(ctx, b.ID)
			if err != nil {
				return nil, err
			}
			b = full
		}
		if fmt.Sprint(b.TemplateParameters["imageTag"]) == imageTag {
			return b, nil
		}
	}
	return nil, nil
}

func (a *adoClient) queueBuild(ctx context.Context, pipelineID int, branch, imageTag string) (*buildInfo, error) {
	body := map[string]any{
		"definition":   map[string]int{"id": pipelineID},
		"sourceBranch": a.sourceBranch,
		"templateParameters": map[string]string{
			"branch":   branch,
			"imageTag": imageTag,
		},
	}
	var b buildInfo
	if err := a.doJSON(ctx, http.MethodPost, a.buildsURL()+"?api-version=7.1", body, &b); err != nil {
		return nil, err
	}
	if b.ID == 0 {
		return nil, errors.New("ADO queue response has no build id")
	}
	return &b, nil
}

func (a *adoClient) getBuild(ctx context.Context, buildID int) (*buildInfo, error) {
	var b buildInfo
	u := fmt.Sprintf("%s/%d?api-version=7.1", a.buildsURL(), buildID)
	if err := a.doJSON(ctx, http.MethodGet, u, nil, &b); err != nil {
		return nil, err
	}
	return &b, nil
}

// buildLink returns the web link of a build. It builds the link when the
// API did not send one.
func buildLink(org, project string, b *buildInfo) string {
	if u := b.webURL(); u != "" {
		return u
	}
	return fmt.Sprintf("https://dev.azure.com/%s/%s/_build/results?buildId=%d", url.PathEscape(org), url.PathEscape(project), b.ID)
}

// redactQuery removes the query string from a URL, for error messages.
func redactQuery(u string) string {
	if i := strings.IndexByte(u, '?'); i >= 0 {
		return u[:i]
	}
	return u
}
