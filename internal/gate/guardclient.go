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
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
)

// GuardClient calls the portcullis-guard token API on behalf of Gate.
// It is used to claim approved escalation tokens and to poll for tokens that
// were approved by remote workflows (e.g. ServiceNow) without user interaction.
type GuardClient struct {
	endpoint    string
	bearerToken string
	client      *http.Client
}

// NewGuardClient creates a GuardClient for the given Guard endpoint.
func NewGuardClient(cfg GuardConfig) *GuardClient {
	return &GuardClient{
		endpoint:    cfg.Endpoint,
		bearerToken: cfg.BearerToken,
		client:      &http.Client{},
	}
}

// unclaimedTokenInfo describes a single unclaimed token returned by Guard.
type unclaimedTokenInfo struct {
	JTI string `json:"jti"`
	Raw string `json:"raw"`
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
//
// No authentication is required for this endpoint: the JTI serves as a
// capability token — an attacker would need to already know the JTI (a random
// UUID) to make a meaningful claim, and the token itself is still validated
// by the PDP before being honoured. This design follows the principle that the
// security boundary is the JTI secret, not a transport credential.
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

