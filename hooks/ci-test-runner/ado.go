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
// Types
// ---------------------------------------------------------------------------

// buildInfo is the subset of an Azure DevOps build that the runner uses.
type buildInfo struct {
	BuildNumber string `json:"buildNumber"`
	Status      string `json:"status"`
	Result      string `json:"result"`
	URI         string `json:"uri"` // vstfs:///Build/Build/<id>
	Links       struct {
		Web struct {
			Href string `json:"href"`
		} `json:"web"`
	} `json:"_links"`
	ID int `json:"id"`
}

// testRun is the subset of an Azure DevOps test run that the runner uses.
// Field names are those of the Test Runs REST API. ADO counts a failed test
// that nobody analyzed yet in unanalyzedTests.
type testRun struct {
	TotalTests         int `json:"totalTests"`
	PassedTests        int `json:"passedTests"`
	UnanalyzedTests    int `json:"unanalyzedTests"`
	IncompleteTests    int `json:"incompleteTests"`
	NotApplicableTests int `json:"notApplicableTests"`
}

// ciProvider talks to Azure DevOps. Abstracted for testing.
type ciProvider interface {
	// queueBuild queues a build of the pipeline on sourceBranch with the
	// template parameters params.
	queueBuild(ctx context.Context, pipelineID int, sourceBranch string, params map[string]string) (*buildInfo, error)
	// getBuild returns the current state of a build.
	getBuild(ctx context.Context, buildID int) (*buildInfo, error)
	// testRuns returns the test runs that a build published.
	testRuns(ctx context.Context, buildURI string) ([]testRun, error)
	// buildLink returns the web link of a build.
	buildLink(b *buildInfo) string
	// ping gets an Azure DevOps token. It is used by /readyz.
	ping(ctx context.Context) error
}

// errADOAuth marks a failure to get Azure DevOps credentials.
var errADOAuth = errors.New("azure devops authentication")

// adoStatusError is an Azure DevOps answer with an unexpected HTTP status.
type adoStatusError struct {
	Method string
	URL    string // without the query string
	Body   string
	// RetryAfter is the delay of a Retry-After header (for example on 429),
	// or 0.
	RetryAfter time.Duration
	Status     int
}

func (e *adoStatusError) Error() string {
	return fmt.Sprintf("ADO %s %s returned status %d: %s", e.Method, e.URL, e.Status, e.Body)
}

// shortError returns a short text for err that is safe to show to users.
// It never contains a URL, a token or a response body. The pod log gets
// the full error.
func shortError(err error) string {
	var se *adoStatusError
	switch {
	case errors.As(err, &se) && se.Status == http.StatusNonAuthoritativeInfo:
		return "Azure DevOps refused the credentials"
	case errors.As(err, &se):
		return fmt.Sprintf("Azure DevOps returned status %d", se.Status)
	case errors.Is(err, errADOAuth):
		return "cannot get an Azure DevOps token"
	case errors.Is(err, context.DeadlineExceeded):
		return "Azure DevOps did not answer in time"
	case errors.Is(err, context.Canceled):
		return "the request was canceled"
	default:
		return "the request to Azure DevOps failed"
	}
}

// ---------------------------------------------------------------------------
// ADO client
// ---------------------------------------------------------------------------

type adoClient struct {
	entra   *entraTokenSource
	client  *http.Client
	baseURL string // https://dev.azure.com; tests point it at a fake server
	org     string
	project string
	mode    string // authWorkloadIdentity or authPAT
	pat     string
}

func newADOClient(org, project, mode, pat string, entra *entraTokenSource) *adoClient {
	return &adoClient{
		baseURL: "https://dev.azure.com",
		org:     org,
		project: project,
		mode:    mode,
		pat:     pat,
		entra:   entra,
		client:  &http.Client{Timeout: 30 * time.Second},
	}
}

func (a *adoClient) authHeader(ctx context.Context) (string, error) {
	switch a.mode {
	case authWorkloadIdentity:
		if a.entra == nil {
			return "", fmt.Errorf("%w: workload identity credential is not configured", errADOAuth)
		}
		tok, err := a.entra.token(ctx, adoScope)
		if err != nil {
			return "", fmt.Errorf("%w: entra token: %w", errADOAuth, err)
		}
		return "Bearer " + tok, nil
	case authPAT:
		if a.pat == "" {
			return "", fmt.Errorf("%w: ADO_PAT is not set", errADOAuth)
		}
		return basicAuth("", a.pat), nil
	default:
		return "", fmt.Errorf("%w: not configured", errADOAuth)
	}
}

func (a *adoClient) ping(ctx context.Context) error {
	if a.org == "" || a.project == "" {
		return errors.New("ADO_ORG or ADO_PROJECT is not set")
	}
	_, err := a.authHeader(ctx)
	return err
}

func (a *adoClient) projectURL() string {
	return fmt.Sprintf("%s/%s/%s", a.baseURL, url.PathEscape(a.org), url.PathEscape(a.project))
}

func (a *adoClient) buildsURL() string {
	return a.projectURL() + "/_apis/build/builds"
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
		return &adoStatusError{
			Method:     method,
			URL:        redactQuery(u),
			Status:     resp.StatusCode,
			Body:       strings.TrimSpace(string(msg)),
			RetryAfter: parseRetryAfter(resp.Header.Get("Retry-After"), time.Now()),
		}
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(out); err != nil {
		return fmt.Errorf("decode ADO response: %w", err)
	}
	return nil
}

func (a *adoClient) queueBuild(ctx context.Context, pipelineID int, sourceBranch string, params map[string]string) (*buildInfo, error) {
	body := map[string]any{
		"definition":         map[string]int{"id": pipelineID},
		"sourceBranch":       sourceBranch,
		"templateParameters": params,
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

func (a *adoClient) testRuns(ctx context.Context, buildURI string) ([]testRun, error) {
	q := url.Values{
		"buildUri":          {buildURI},
		"includeRunDetails": {"true"},
		"api-version":       {"7.1"},
	}
	var result struct {
		Value []testRun `json:"value"`
	}
	if err := a.doJSON(ctx, http.MethodGet, a.projectURL()+"/_apis/test/runs?"+q.Encode(), nil, &result); err != nil {
		return nil, err
	}
	return result.Value, nil
}

// buildLink returns the web link of a build. It builds the link when the
// API did not send one.
func (a *adoClient) buildLink(b *buildInfo) string {
	if u := b.Links.Web.Href; u != "" {
		return u
	}
	return fmt.Sprintf("%s/_build/results?buildId=%d", a.projectURL(), b.ID)
}

// buildURI returns the artifact URI of a build, which the Test Runs API
// takes as buildUri.
func buildURI(b *buildInfo) string {
	if b.URI != "" {
		return b.URI
	}
	return "vstfs:///Build/Build/" + strconv.Itoa(b.ID)
}

// testResultsLink returns the link to the Tests tab of a build page.
func testResultsLink(buildURL string) string {
	sep := "?"
	if strings.Contains(buildURL, "?") {
		sep = "&"
	}
	return buildURL + sep + "view=ms.vss-test-web.build-test-results-tab"
}

// retryAfter returns the Retry-After delay of err, or 0.
func retryAfter(err error) time.Duration {
	var se *adoStatusError
	if errors.As(err, &se) {
		return se.RetryAfter
	}
	return 0
}

// parseRetryAfter reads a Retry-After header: a number of seconds or an
// HTTP date. It returns 0 for a missing or invalid value, or a past date.
func parseRetryAfter(v string, now time.Time) time.Duration {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0
	}
	if n, err := strconv.Atoi(v); err == nil {
		if n <= 0 {
			return 0
		}
		return time.Duration(n) * time.Second
	}
	if t, err := http.ParseTime(v); err == nil && t.After(now) {
		return t.Sub(now)
	}
	return 0
}

// redactQuery removes the query string from a URL, for error messages.
func redactQuery(u string) string {
	if i := strings.IndexByte(u, '?'); i >= 0 {
		return u[:i]
	}
	return u
}
