package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------
// Registry — Azure Container Registry, Docker Registry HTTP API v2
// ---------------------------------------------------------------------------

// manifestAccept lists the manifest types the gate reads and copies.
const manifestAccept = "application/vnd.oci.image.index.v1+json, " +
	"application/vnd.oci.image.manifest.v1+json, " +
	"application/vnd.docker.distribution.manifest.list.v2+json, " +
	"application/vnd.docker.distribution.manifest.v2+json"

// maxManifestSize limits the size of a manifest the gate reads.
const maxManifestSize = 4 << 20 // 4 MiB

// manifest is a raw image manifest or image index.
type manifest struct {
	contentType string
	digest      string
	body        []byte
}

// registryClient reads and writes image manifests.
type registryClient interface {
	// headDigest returns the digest of repo:ref, or "" when it does not exist.
	headDigest(ctx context.Context, repo, ref string) (string, error)
	// getManifest returns the manifest of repo:ref, or nil when it does not exist.
	getManifest(ctx context.Context, repo, ref string) (*manifest, error)
	// putManifest stores m under repo:tag.
	putManifest(ctx context.Context, repo, tag string, m *manifest) error
	// ping gets a registry token. It is used by /readyz.
	ping(ctx context.Context) error
}

type acrClient struct {
	entra    *entraTokenSource
	tokens   *tokenCache
	client   *http.Client
	host     string // registry host, also the token "service"
	baseURL  string // scheme + host; tests point it at a fake server
	mode     string // authWorkloadIdentity or authBasic
	username string
	password string
	tenantID string
}

// normalizeRegistryHost removes a scheme and a trailing slash.
func normalizeRegistryHost(s string) string {
	s = strings.TrimPrefix(s, "https://")
	s = strings.TrimPrefix(s, "http://")
	return strings.TrimRight(s, "/")
}

func newACRClient(host, mode, username, password, tenantID string, entra *entraTokenSource) *acrClient {
	host = normalizeRegistryHost(host)
	return &acrClient{
		host:     host,
		baseURL:  "https://" + host,
		mode:     mode,
		username: username,
		password: password,
		tenantID: tenantID,
		entra:    entra,
		tokens:   newTokenCache(),
		client:   &http.Client{Timeout: 30 * time.Second},
	}
}

func (r *acrClient) headDigest(ctx context.Context, repo, ref string) (string, error) {
	resp, err := r.do(ctx, repo, http.MethodHead, "/v2/"+repo+"/manifests/"+ref, nil, "")
	if err != nil {
		return "", err
	}
	resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		return "", nil
	default:
		return "", fmt.Errorf("registry HEAD %s:%s returned status %d", repo, ref, resp.StatusCode)
	}
	if d := resp.Header.Get("Docker-Content-Digest"); d != "" {
		return d, nil
	}
	// The registry did not send the digest. Read the manifest to compute it.
	m, err := r.getManifest(ctx, repo, ref)
	if err != nil || m == nil {
		return "", err
	}
	return m.digest, nil
}

func (r *acrClient) getManifest(ctx context.Context, repo, ref string) (*manifest, error) {
	resp, err := r.do(ctx, repo, http.MethodGet, "/v2/"+repo+"/manifests/"+ref, nil, "")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		return nil, nil
	default:
		return nil, fmt.Errorf("registry GET %s:%s returned status %d", repo, ref, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxManifestSize))
	if err != nil {
		return nil, fmt.Errorf("read manifest %s:%s: %w", repo, ref, err)
	}
	sum := sha256.Sum256(body)
	digest := "sha256:" + hex.EncodeToString(sum[:])
	if d := resp.Header.Get("Docker-Content-Digest"); d != "" && d != digest {
		return nil, fmt.Errorf("manifest %s:%s digest mismatch: header %s, body %s", repo, ref, d, digest)
	}
	return &manifest{contentType: resp.Header.Get("Content-Type"), digest: digest, body: body}, nil
}

func (r *acrClient) putManifest(ctx context.Context, repo, tag string, m *manifest) error {
	resp, err := r.do(ctx, repo, http.MethodPut, "/v2/"+repo+"/manifests/"+tag, m.body, m.contentType)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("registry PUT %s:%s returned status %d: %s", repo, tag, resp.StatusCode, strings.TrimSpace(string(msg)))
	}
	return nil
}

func (r *acrClient) ping(ctx context.Context) error {
	if r.host == "" {
		return errors.New("REGISTRY_URL is not set")
	}
	switch r.mode {
	case authWorkloadIdentity:
		_, err := r.refreshToken(ctx)
		return err
	case authBasic:
		u := fmt.Sprintf("%s/oauth2/token?service=%s", r.baseURL, url.QueryEscape(r.host))
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", basicAuth(r.username, r.password))
		resp, err := r.client.Do(req)
		if err != nil {
			return fmt.Errorf("registry token request: %w", err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("registry token request returned status %d", resp.StatusCode)
		}
		return nil
	default:
		return errors.New("registry authentication is not configured")
	}
}

// do sends an authenticated /v2 request. When the registry refuses a cached
// token, it gets a new token and tries once more.
func (r *acrClient) do(ctx context.Context, repo, method, path string, body []byte, contentType string) (*http.Response, error) {
	for attempt := 0; ; attempt++ {
		token, err := r.accessToken(ctx, repo)
		if err != nil {
			return nil, fmt.Errorf("registry token for %s: %w", repo, err)
		}
		var rd io.Reader
		if body != nil {
			rd = bytes.NewReader(body)
		}
		req, err := http.NewRequestWithContext(ctx, method, r.baseURL+path, rd)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+token)
		if method == http.MethodPut {
			req.Header.Set("Content-Type", contentType)
		} else {
			req.Header.Set("Accept", manifestAccept)
		}
		resp, err := r.client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("registry %s %s: %w", method, path, err)
		}
		if resp.StatusCode == http.StatusUnauthorized && attempt == 0 {
			resp.Body.Close()
			r.tokens.drop("repo:" + repo)
			r.tokens.drop("refresh")
			continue
		}
		return resp, nil
	}
}

// accessToken returns a registry access token with pull and push rights on repo.
func (r *acrClient) accessToken(ctx context.Context, repo string) (string, error) {
	key := "repo:" + repo
	if v, ok := r.tokens.get(key); ok {
		return v, nil
	}
	scope := "repository:" + repo + ":pull,push"

	var req *http.Request
	var err error
	switch r.mode {
	case authWorkloadIdentity:
		refresh, rerr := r.refreshToken(ctx)
		if rerr != nil {
			return "", rerr
		}
		form := url.Values{
			"grant_type":    {"refresh_token"},
			"service":       {r.host},
			"scope":         {scope},
			"refresh_token": {refresh},
		}
		req, err = http.NewRequestWithContext(ctx, http.MethodPost, r.baseURL+"/oauth2/token", strings.NewReader(form.Encode()))
		if err != nil {
			return "", err
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	case authBasic:
		u := fmt.Sprintf("%s/oauth2/token?service=%s&scope=%s", r.baseURL, url.QueryEscape(r.host), url.QueryEscape(scope))
		req, err = http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return "", err
		}
		req.Header.Set("Authorization", basicAuth(r.username, r.password))
	default:
		return "", errors.New("registry authentication is not configured")
	}

	var tok struct {
		AccessToken string `json:"access_token"`
	}
	if err := r.postToken(req, &tok); err != nil {
		return "", fmt.Errorf("token request: %w", err)
	}
	if tok.AccessToken == "" {
		return "", errors.New("token response has no access_token")
	}
	r.tokens.put(key, tok.AccessToken, tokenExpiry(tok.AccessToken, r.tokens.now()))
	return tok.AccessToken, nil
}

// refreshToken exchanges an Entra ID token for an ACR refresh token.
func (r *acrClient) refreshToken(ctx context.Context) (string, error) {
	if v, ok := r.tokens.get("refresh"); ok {
		return v, nil
	}
	if r.entra == nil {
		return "", errors.New("workload identity credential is not configured")
	}
	aad, err := r.entra.token(ctx, acrScope)
	if err != nil {
		return "", fmt.Errorf("entra token for registry: %w", err)
	}
	form := url.Values{
		"grant_type":   {"access_token"},
		"service":      {r.host},
		"access_token": {aad},
	}
	if r.tenantID != "" {
		form.Set("tenant", r.tenantID)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.baseURL+"/oauth2/exchange", strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	var tok struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := r.postToken(req, &tok); err != nil {
		return "", fmt.Errorf("registry token exchange: %w", err)
	}
	if tok.RefreshToken == "" {
		return "", errors.New("registry token exchange returned no refresh_token")
	}
	r.tokens.put("refresh", tok.RefreshToken, tokenExpiry(tok.RefreshToken, r.tokens.now()))
	return tok.RefreshToken, nil
}

// postToken sends a token request and decodes the JSON response into out.
// Error messages never contain the response body, because a body can hold
// a token.
func (r *acrClient) postToken(req *http.Request, out any) error {
	resp, err := r.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(out); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	return nil
}

// shortDigest returns the first 12 hex characters of a digest, for logs.
func shortDigest(d string) string {
	d = strings.TrimPrefix(d, "sha256:")
	if len(d) > 12 {
		return d[:12]
	}
	return d
}
