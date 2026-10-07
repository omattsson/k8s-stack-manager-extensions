package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"sync"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
)

// Authentication modes.
const (
	authWorkloadIdentity = "workload-identity"
	authBasic            = "basic"
	authPAT              = "pat"
)

// Entra ID scopes.
const (
	acrScope = "https://containerregistry.azure.net/.default"
	adoScope = "499b84ac-1321-427f-aa17-267ca6975798/.default"
)

// tokenRefreshSkew is the time before expiry at which a cached token is
// replaced.
const tokenRefreshSkew = 2 * time.Minute

// fallbackTokenLifetime is used when a token does not tell its expiry.
const fallbackTokenLifetime = 5 * time.Minute

// ---------------------------------------------------------------------------
// Token cache
// ---------------------------------------------------------------------------

type cachedToken struct {
	expires time.Time
	value   string
}

// tokenCache keeps tokens until shortly before they expire.
type tokenCache struct {
	m   map[string]cachedToken
	now func() time.Time
	mu  sync.Mutex
}

func newTokenCache() *tokenCache {
	return &tokenCache{m: make(map[string]cachedToken), now: time.Now}
}

func (c *tokenCache) get(key string) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	t, ok := c.m[key]
	if !ok || !c.now().Before(t.expires.Add(-tokenRefreshSkew)) {
		return "", false
	}
	return t.value, true
}

func (c *tokenCache) put(key, value string, expires time.Time) {
	c.mu.Lock()
	c.m[key] = cachedToken{value: value, expires: expires}
	c.mu.Unlock()
}

func (c *tokenCache) drop(key string) {
	c.mu.Lock()
	delete(c.m, key)
	c.mu.Unlock()
}

// ---------------------------------------------------------------------------
// Entra ID tokens
// ---------------------------------------------------------------------------

// entraTokenSource gets Entra ID access tokens from a credential.
// In production the credential is azidentity.WorkloadIdentityCredential.
// Tests use a fake credential.
type entraTokenSource struct {
	cred  azcore.TokenCredential
	cache *tokenCache
}

func newEntraTokenSource(cred azcore.TokenCredential) *entraTokenSource {
	return &entraTokenSource{cred: cred, cache: newTokenCache()}
}

func (e *entraTokenSource) token(ctx context.Context, scope string) (string, error) {
	if v, ok := e.cache.get(scope); ok {
		return v, nil
	}
	tok, err := e.cred.GetToken(ctx, policy.TokenRequestOptions{Scopes: []string{scope}})
	if err != nil {
		return "", err
	}
	exp := tok.ExpiresOn
	if exp.IsZero() {
		exp = e.cache.now().Add(fallbackTokenLifetime)
	}
	e.cache.put(scope, tok.Token, exp)
	return tok.Token, nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// jwtExpiry reads the "exp" claim of a JWT. It does not verify the token.
// It returns the zero time when the claim is not readable.
func jwtExpiry(token string) time.Time {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return time.Time{}
	}
	payload, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[1], "="))
	if err != nil {
		return time.Time{}
	}
	var claims struct {
		Exp int64 `json:"exp"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil || claims.Exp == 0 {
		return time.Time{}
	}
	return time.Unix(claims.Exp, 0)
}

// tokenExpiry returns the expiry of a token, or now + fallbackTokenLifetime.
func tokenExpiry(token string, now time.Time) time.Time {
	if exp := jwtExpiry(token); !exp.IsZero() {
		return exp
	}
	return now.Add(fallbackTokenLifetime)
}

func basicAuth(user, pass string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))
}

// resolveAuthMode selects an authentication mode.
// An explicit value wins. Without one, workload identity is used when
// AZURE_CLIENT_ID is set, else the static mode when its values are set.
// It returns "" when no mode is usable.
func resolveAuthMode(explicit, staticMode string, wiAvailable, staticAvailable bool) (string, bool) {
	switch explicit {
	case authWorkloadIdentity, staticMode:
		return explicit, true
	case "":
	default:
		return "", false
	}
	if wiAvailable {
		return authWorkloadIdentity, true
	}
	if staticAvailable {
		return staticMode, true
	}
	return "", true
}
