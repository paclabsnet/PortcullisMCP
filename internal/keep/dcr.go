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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

// ErrDCRNotSupported is returned by RegisterDynamicClient when the IdP responds
// with HTTP 404 or 405, indicating it does not support RFC 7591.
var ErrDCRNotSupported = errors.New("IdP does not support RFC 7591 Dynamic Client Registration")

const (
	// dcrDefaultTimeout is used when BackendDCR.Timeout is zero.
	dcrDefaultTimeout = 10 * time.Second
	// dcrProtocolMismatchTTL is the negative-cache TTL for ErrDCRNotSupported failures.
	dcrProtocolMismatchTTL = 1 * time.Hour
)

// dcrRegistrationRequest is the RFC 7591 client metadata request payload.
type dcrRegistrationRequest struct {
	RedirectURIs            []string `json:"redirect_uris"`
	ClientName              string   `json:"client_name,omitempty"`
	ResponseTypes           []string `json:"response_types"`
	GrantTypes              []string `json:"grant_types"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	Scope                   string   `json:"scope,omitempty"`
	SoftwareStatement       string   `json:"software_statement,omitempty"`
}

// dcrRegistrationResponse is the RFC 7591 client registration response.
type dcrRegistrationResponse struct {
	ClientID                string `json:"client_id"`
	ClientSecret            string `json:"client_secret,omitempty"`
	ClientSecretExpiresAt   int64  `json:"client_secret_expires_at,omitempty"`
	TokenEndpointAuthMethod string `json:"token_endpoint_auth_method,omitempty"`
	Scope                   string `json:"scope,omitempty"`
	// Error fields — present when registration fails.
	Error            string `json:"error,omitempty"`
	ErrorDescription string `json:"error_description,omitempty"`
}

// RegisterDynamicClient performs an RFC 7591 client registration and returns
// the resulting clientReg. The provided http.Client is used for the request.
func RegisterDynamicClient(ctx context.Context, httpClient *http.Client, oauthCfg *BackendOAuth) (*clientReg, error) {
	// 0. Determine the effective timeout, then derive a child context.
	timeout := oauthCfg.DCR.Timeout
	if timeout <= 0 {
		timeout = dcrDefaultTimeout
	}
	if dl, ok := ctx.Deadline(); ok {
		if remaining := time.Until(dl); remaining < timeout {
			timeout = remaining
		}
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// 1. Build the grant_types list.
	grantTypes := []string{"authorization_code"}
	if oauthCfg.StoreRefreshTokens {
		grantTypes = append(grantTypes, "refresh_token")
	}

	// 2. Build the request payload.
	payload := dcrRegistrationRequest{
		RedirectURIs:            []string{oauthCfg.CallbackURL},
		ClientName:              oauthCfg.DCR.ClientName,
		ResponseTypes:           []string{"code"},
		GrantTypes:              grantTypes,
		TokenEndpointAuthMethod: "client_secret_basic",
		Scope:                   strings.Join(oauthCfg.EffectiveScopes(), " "),
	}
	if oauthCfg.DCR.SoftwareStatement != "" {
		payload.SoftwareStatement = oauthCfg.DCR.SoftwareStatement
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("dcr: marshal request: %w", err)
	}

	// 3. Build the HTTP request.
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, oauthCfg.DCR.RegistrationEndpoint, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("dcr: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	// Attach the Initial Access Token if provided.
	if oauthCfg.DCR.InitialAccessToken != "" {
		req.Header.Set("Authorization", "Bearer "+oauthCfg.DCR.InitialAccessToken)
	}

	debugLogDCRRequest("keep: DCR→ registration request", payload, oauthCfg.DCR.RegistrationEndpoint,
		oauthCfg.DCR.InitialAccessToken != "", oauthCfg.DCR.SoftwareStatement != "")
	if oauthCfg.DCR.InitialAccessToken != "" {
		debugLogBearerToken("keep: DCR→ Initial Access Token", oauthCfg.DCR.InitialAccessToken)
	}

	// 4. Send the request.
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("dcr: http request: %w", err)
	}
	defer resp.Body.Close()

	// 5. Handle protocol-not-supported responses.
	if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusMethodNotAllowed {
		return nil, ErrDCRNotSupported
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("dcr: read response body: %w", err)
	}

	// 6. Parse the JSON response.
	var regResp dcrRegistrationResponse
	if err := json.Unmarshal(respBody, &regResp); err != nil {
		slog.Debug("keep: DCR← failed to parse response body", "status", resp.StatusCode, "body", string(respBody))
		return nil, fmt.Errorf("dcr: parse response (status %d): %w", resp.StatusCode, err)
	}
	debugLogDCRResponse("keep: DCR← registration response", regResp, resp.StatusCode)

	// 7. Surface IdP-level errors (RFC 7591 section 3.2.2).
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		if regResp.Error != "" {
			return nil, fmt.Errorf("dcr: registration failed: %s: %s", regResp.Error, regResp.ErrorDescription)
		}
		return nil, fmt.Errorf("dcr: unexpected status %d", resp.StatusCode)
	}

	if regResp.ClientID == "" {
		return nil, fmt.Errorf("dcr: IdP did not return a client_id")
	}

	// 8. Scope validation — warn if the IdP granted fewer scopes than requested.
	if regResp.Scope != "" && regResp.Scope != payload.Scope {
		granted := strings.Fields(regResp.Scope)
		requested := strings.Fields(payload.Scope)
		missing := scopeDifference(requested, granted)
		if len(missing) > 0 {
			slog.Warn("dcr: IdP granted fewer scopes than requested",
				"requested", payload.Scope,
				"granted", regResp.Scope,
				"missing", strings.Join(missing, " "),
			)
		}
	}

	// 9. Build and return the clientReg.
	authMethod := regResp.TokenEndpointAuthMethod
	if authMethod == "" {
		authMethod = "client_secret_basic" // RFC 7591 default / maximum-compatibility fallback
	}

	return &clientReg{
		ClientID:                regResp.ClientID,
		ClientSecret:            regResp.ClientSecret,
		ClientSecretExpiresAt:   regResp.ClientSecretExpiresAt,
		TokenEndpointAuthMethod: authMethod,
		Scopes:                  regResp.Scope,
	}, nil
}

// scopeDifference returns elements in 'want' that are not in 'have'.
func scopeDifference(want, have []string) []string {
	haveSet := make(map[string]struct{}, len(have))
	for _, s := range have {
		haveSet[s] = struct{}{}
	}
	var missing []string
	for _, s := range want {
		if _, ok := haveSet[s]; !ok {
			missing = append(missing, s)
		}
	}
	return missing
}
