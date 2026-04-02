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

package gate

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"time"
)

// GuardClient calls the portcullis-guard token API on behalf of Gate.
// It is used to claim approved escalation tokens and to poll for tokens that
// were approved by remote workflows (e.g. ServiceNow) without user interaction.
type GuardClient struct {
	endpoint    string
	bearerToken string
	client      *http.Client
}

// NewGuardClient creates a GuardClient for the given Guard config.
// If auth.mtls is configured, the client uses mutual TLS; otherwise plain HTTPS
// with an optional bearer token.
// Returns an error if TLS material cannot be loaded.
func NewGuardClient(cfg GuardConfig) (*GuardClient, error) {
	transport, err := buildGuardTransport(cfg.Auth.Mtls)
	if err != nil {
		return nil, fmt.Errorf("build guard transport: %w", err)
	}
	return &GuardClient{
		endpoint:    cfg.resolvedAPIEndpoint(),
		bearerToken: cfg.Auth.BearerToken,
		client:      &http.Client{Timeout: 10 * time.Second, Transport: transport},
	}, nil
}

// buildGuardTransport builds an http.RoundTripper for Guard API calls.
// When mtls.client_cert and mtls.client_key are set, mTLS is enabled.
// When mtls.server_ca is set, Guard's server certificate is verified against that CA.
func buildGuardTransport(mtls MtlsClientConfig) (http.RoundTripper, error) {
	base := http.DefaultTransport.(*http.Transport).Clone()
	if base.TLSClientConfig == nil {
		base.TLSClientConfig = &tls.Config{} //nolint:gosec // MinVersion set on Guard server
	}
	base.TLSClientConfig.MinVersion = tls.VersionTLS13

	if mtls.ServerCA != "" {
		caData, err := os.ReadFile(mtls.ServerCA)
		if err != nil {
			return nil, fmt.Errorf("read guard server CA %q: %w", mtls.ServerCA, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caData) {
			return nil, fmt.Errorf("parse guard server CA %q: no valid certificates found", mtls.ServerCA)
		}
		base.TLSClientConfig.RootCAs = pool
	}

	if mtls.ClientCert != "" || mtls.ClientKey != "" {
		if mtls.ClientCert == "" || mtls.ClientKey == "" {
			return nil, fmt.Errorf("guard auth.mtls requires both client_cert and client_key")
		}
		cert, err := tls.LoadX509KeyPair(mtls.ClientCert, mtls.ClientKey)
		if err != nil {
			return nil, fmt.Errorf("load guard client keypair: %w", err)
		}
		base.TLSClientConfig.Certificates = []tls.Certificate{cert}
	}

	return base, nil
}

// unclaimedTokenInfo describes a single unclaimed token returned by Guard.
type unclaimedTokenInfo struct {
	JTI       string    `json:"jti"`
	Raw       string    `json:"raw"`
	ExpiresAt time.Time `json:"expires_at"`
}

// ListUnclaimedTokens returns all tokens that Guard holds for userID but have
// not yet been claimed. These include tokens approved via the web UI or by a
// remote workflow (e.g. ServiceNow posting to /token/deposit).
// Requires auth: bearer token.
func (g *GuardClient) ListUnclaimedTokens(ctx context.Context, userID string) ([]unclaimedTokenInfo, error) {
	u, err := url.Parse(g.endpoint + "/token/unclaimed/list")
	if err != nil {
		return nil, fmt.Errorf("parse guard url: %w", err)
	}
	q := u.Query()
	q.Set("user_id", userID)
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("build guard request: %w", err)
	}
	if g.bearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+g.bearerToken)
	}

	resp, err := g.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("guard request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var errBody struct {
			Error string `json:"error"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&errBody)
		return nil, fmt.Errorf("guard returned %d: %s", resp.StatusCode, errBody.Error)
	}

	var tokens []unclaimedTokenInfo
	if err := json.NewDecoder(resp.Body).Decode(&tokens); err != nil {
		return nil, fmt.Errorf("decode guard response: %w", err)
	}
	return tokens, nil
}

// RegisterPending pushes a Keep-signed pending escalation JWT to Guard so that
// Guard can serve a short ?jti= approval URL rather than embedding the full JWT
// in the query string. Guard validates the JWT signature on receipt to prevent
// rogue Gate instances from registering arbitrary JWTs.
// POST /pending  body: {"jti": "...", "jwt": "..."}
// Requires bearer auth.
func (g *GuardClient) RegisterPending(ctx context.Context, jti, jwt string) error {
	u := g.endpoint + "/pending"

	body, err := json.Marshal(map[string]string{"jti": jti, "jwt": jwt})
	if err != nil {
		return fmt.Errorf("marshal pending request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build pending request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if g.bearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+g.bearerToken)
	}

	resp, err := g.client.Do(req)
	if err != nil {
		return fmt.Errorf("register pending request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		var errBody struct {
			Error string `json:"error"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&errBody)
		return fmt.Errorf("guard register pending returned %d: %s", resp.StatusCode, errBody.Error)
	}
	return nil
}

// ClaimToken atomically removes the token identified by jti from Guard's
// unclaimed list and returns its raw JWT. Returns an empty string (and no
// error) when the token does not exist in the unclaimed list — this is the
// normal case when the user has not yet approved the escalation request.
func (g *GuardClient) ClaimToken(ctx context.Context, jti string) (string, error) {
	u := g.endpoint + "/token/claim"

	body, err := json.Marshal(map[string]string{"jti": jti})
	if err != nil {
		return "", fmt.Errorf("marshal claim request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u,
		bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("build guard claim request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if g.bearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+g.bearerToken)
	}

	resp, err := g.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("guard claim request: %w", err)
	}
	defer resp.Body.Close()

	// 404 means the token is not (yet) in the unclaimed list — not an error.
	if resp.StatusCode == http.StatusNotFound {
		return "", nil
	}
	if resp.StatusCode != http.StatusOK {
		var errBody struct {
			Error string `json:"error"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&errBody)
		return "", fmt.Errorf("guard claim returned %d: %s", resp.StatusCode, errBody.Error)
	}

	var result struct {
		Raw string `json:"raw"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("decode guard claim response: %w", err)
	}
	return result.Raw, nil
}
