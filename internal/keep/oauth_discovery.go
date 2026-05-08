// Copyright 2026 Policy-as-Code Laboratories (PAC.Labs)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package keep

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	discoveryHTTPTimeout  = 10 * time.Second
	discoveryMaxBodyBytes = 64 * 1024 // 64 KB — sufficient for any well-formed metadata doc
)


// oauthEndpoints holds the resolved authorization and token endpoint URLs,
// and the optional RFC 7591 registration endpoint discovered from ASM metadata.
type oauthEndpoints struct {
	AuthorizationEndpoint string
	TokenEndpoint         string
	RegistrationEndpoint  string // populated when DCR is enabled and supported by the IdP
}

// resolveOAuthEndpoints returns the OAuth endpoints for a backend.
//
// If the config carries both authorization_endpoint and token_endpoint they are
// used directly and no network discovery is performed (escape hatch for backends
// that do not publish metadata, or for compliance pin requirements).
//
// Otherwise the full discovery chain is run:
//
//  1. Parse the WWW-Authenticate header from the 401 response.
//  2. Follow resource_metadata (RFC 9728) → PRM → ASM, or as_uri / realm → ASM.
//  3. ASM (RFC 8414 / OIDC Discovery) provides authorization_endpoint and token_endpoint.
func resolveOAuthEndpoints(ctx context.Context, cfg BackendOAuth, wwwAuthenticate string) (oauthEndpoints, error) {
	if cfg.AuthorizationEndpoint != "" && cfg.TokenEndpoint != "" {
		eps := oauthEndpoints{
			AuthorizationEndpoint: cfg.AuthorizationEndpoint,
			TokenEndpoint:         cfg.TokenEndpoint,
		}
		// When DCR is enabled and the registration endpoint is explicitly configured,
		// use it directly; skip any ASM discovery for the registration endpoint.
		if cfg.DCR.Enabled && cfg.DCR.RegistrationEndpoint != "" {
			eps.RegistrationEndpoint = cfg.DCR.RegistrationEndpoint
		}
		if cfg.DCR.Enabled && eps.RegistrationEndpoint == "" {
			return oauthEndpoints{}, fmt.Errorf("dcr is enabled but registration_endpoint is not configured and cannot be discovered when authorization_endpoint is set statically")
		}
		return eps, nil
	}
	client := newHTTPClient(true)
	client.Timeout = discoveryHTTPTimeout
	eps, err := discoverOAuthEndpoints(ctx, client, wwwAuthenticate)
	if err != nil {
		return oauthEndpoints{}, err
	}
	// If DCR is enabled and the static config provides a registration_endpoint, prefer it.
	if cfg.DCR.Enabled && cfg.DCR.RegistrationEndpoint != "" {
		eps.RegistrationEndpoint = cfg.DCR.RegistrationEndpoint
	}
	// Validate that DCR can proceed.
	if cfg.DCR.Enabled && eps.RegistrationEndpoint == "" {
		return oauthEndpoints{}, fmt.Errorf("dcr is enabled but the IdP did not advertise a registration_endpoint in its metadata; " +
			"set dcr.registration_endpoint explicitly or disable dcr")
	}
	return eps, nil
}

// discoverOAuthEndpoints parses the WWW-Authenticate header from a 401 response
// and follows the PRM (RFC 9728) + ASM (RFC 8414) discovery chain.
// client is used for all outbound HTTP calls; callers must supply a client that
// enforces appropriate SSRF restrictions (see newSecureDiscoveryClient).
func discoverOAuthEndpoints(ctx context.Context, client *http.Client, wwwAuthenticate string) (oauthEndpoints, error) {
	if wwwAuthenticate == "" {
		return oauthEndpoints{}, fmt.Errorf("no WWW-Authenticate header in 401 response — " +
			"set authorization_endpoint and token_endpoint in config to skip discovery")
	}

	params := parseBearerParams(wwwAuthenticate)
	if len(params) == 0 {
		return oauthEndpoints{}, fmt.Errorf("WWW-Authenticate header %q does not contain a Bearer challenge — " +
			"set authorization_endpoint and token_endpoint in config to skip discovery", wwwAuthenticate)
	}

	// Priority 1: resource_metadata URL (RFC 9728).
	if prmURL := params["resource_metadata"]; prmURL != "" {
		eps, err := fetchFromPRM(ctx, client, prmURL)
		if err == nil {
			return eps, nil
		}
		// Non-fatal: fall through to other discovery methods and report at the end.
	}

	// Priority 2: as_uri — direct authorization server issuer URI.
	if asURI := params["as_uri"]; asURI != "" {
		eps, err := fetchASM(ctx, client, asURI)
		if err == nil {
			return eps, nil
		}
	}

	// Priority 3: realm — treat as issuer for ASM discovery.
	if realm := params["realm"]; realm != "" {
		eps, err := fetchASM(ctx, client, realm)
		if err == nil {
			return eps, nil
		}
	}

	return oauthEndpoints{}, fmt.Errorf(
		"OAuth endpoint discovery failed for WWW-Authenticate %q — "+
			"set authorization_endpoint and token_endpoint in config to skip discovery",
		wwwAuthenticate,
	)
}

// parseBearerParams parses the parameters from the first Bearer challenge in a
// WWW-Authenticate header value.  Returns a map of lowercase parameter names to
// their unquoted values.  Returns an empty map if no Bearer challenge is found.
//
// Example:
//
//	Bearer realm="https://auth.example.com", resource_metadata="https://api.example.com/.well-known/oauth-protected-resource"
func parseBearerParams(header string) map[string]string {
	params := make(map[string]string)
	// Find the first "Bearer" token (case-insensitive).
	lower := strings.ToLower(header)
	idx := strings.Index(lower, "bearer")
	if idx < 0 {
		return params
	}
	rest := strings.TrimSpace(header[idx+len("bearer"):])
	if rest == "" {
		return params
	}

	// Split on commas, but be careful not to split inside quoted strings.
	for len(rest) > 0 {
		// Skip leading whitespace.
		rest = strings.TrimSpace(rest)
		if rest == "" {
			break
		}
		// Find the key.
		eqIdx := strings.IndexByte(rest, '=')
		if eqIdx < 0 {
			break
		}
		key := strings.ToLower(strings.TrimSpace(rest[:eqIdx]))
		rest = rest[eqIdx+1:]

		// Parse the value — either a quoted string or a token.
		var val string
		if len(rest) > 0 && rest[0] == '"' {
			// Quoted string: scan for the closing quote.
			end := strings.IndexByte(rest[1:], '"')
			if end < 0 {
				// Unterminated quote — take the rest.
				val = rest[1:]
				rest = ""
			} else {
				val = rest[1 : end+1]
				rest = rest[end+2:]
			}
		} else {
			// Unquoted token: ends at comma or end of string.
			commaIdx := strings.IndexByte(rest, ',')
			if commaIdx < 0 {
				val = strings.TrimSpace(rest)
				rest = ""
			} else {
				val = strings.TrimSpace(rest[:commaIdx])
				rest = rest[commaIdx+1:]
			}
		}
		// Advance past any trailing comma.
		rest = strings.TrimLeft(rest, ", ")
		if key != "" && val != "" {
			params[key] = val
		}
	}
	return params
}

// prmDocument is the JSON shape of an OAuth 2.0 Protected Resource Metadata
// document (RFC 9728).
type prmDocument struct {
	Resource              string   `json:"resource"`
	AuthorizationServers  []string `json:"authorization_servers"`
	// Some resource servers embed endpoint URLs directly in the PRM.
	AuthorizationEndpoint string   `json:"authorization_endpoint"`
	TokenEndpoint         string   `json:"token_endpoint"`
}

// fetchFromPRM fetches the Protected Resource Metadata document and resolves
// the OAuth endpoints either directly from the PRM or via the first listed
// authorization server's ASM document.
func fetchFromPRM(ctx context.Context, client *http.Client, prmURL string) (oauthEndpoints, error) {
	var prm prmDocument
	if err := fetchDiscoveryJSON(ctx, client, prmURL, &prm); err != nil {
		return oauthEndpoints{}, fmt.Errorf("fetch PRM %q: %w", prmURL, err)
	}
	// If the PRM itself carries both endpoints, no need to follow the AS chain.
	if prm.AuthorizationEndpoint != "" && prm.TokenEndpoint != "" {
		return oauthEndpoints{
			AuthorizationEndpoint: prm.AuthorizationEndpoint,
			TokenEndpoint:         prm.TokenEndpoint,
		}, nil
	}
	if len(prm.AuthorizationServers) == 0 {
		return oauthEndpoints{}, fmt.Errorf("PRM at %q lists no authorization_servers", prmURL)
	}
	return fetchASM(ctx, client, prm.AuthorizationServers[0])
}

// asmDocument is the JSON shape of an OAuth 2.0 Authorization Server Metadata
// document (RFC 8414) or an OpenID Connect Discovery document (OpenID Connect Core 1.0).
type asmDocument struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	RegistrationEndpoint  string `json:"registration_endpoint"` // RFC 7591
}

// fetchASM fetches the Authorization Server Metadata from the standard well-known
// paths defined by RFC 8414, falling back to the OIDC discovery path.
func fetchASM(ctx context.Context, client *http.Client, issuer string) (oauthEndpoints, error) {
	issuer = strings.TrimSuffix(issuer, "/")
	candidates := []string{
		issuer + "/.well-known/oauth-authorization-server",
		issuer + "/.well-known/openid-configuration",
	}
	var lastErr error
	for _, u := range candidates {
		var asm asmDocument
		if err := fetchDiscoveryJSON(ctx, client, u, &asm); err != nil {
			lastErr = err
			continue
		}
		if asm.AuthorizationEndpoint != "" && asm.TokenEndpoint != "" {
			return oauthEndpoints{
				AuthorizationEndpoint: asm.AuthorizationEndpoint,
				TokenEndpoint:         asm.TokenEndpoint,
				RegistrationEndpoint:  asm.RegistrationEndpoint,
			}, nil
		}
	}
	return oauthEndpoints{}, fmt.Errorf("ASM discovery failed for issuer %q (tried %s, %s): %w",
		issuer, candidates[0], candidates[1], lastErr)
}

// fetchDiscoveryJSON performs a GET request to rawURL using client and
// JSON-decodes the response into out. The URL must use https or http.
// The response body is limited to discoveryMaxBodyBytes.
// client must be a client that enforces appropriate SSRF restrictions;
// callers should pass the result of newSecureDiscoveryClient or a test client.
func fetchDiscoveryJSON(ctx context.Context, client *http.Client, rawURL string, out any) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid URL %q: %w", rawURL, err)
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return fmt.Errorf("discovery URL scheme %q not allowed (must be https)", u.Scheme)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d from %q", resp.StatusCode, rawURL)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, discoveryMaxBodyBytes)).Decode(out)
}
