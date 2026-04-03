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
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/paclabsnet/PortcullisMCP/internal/shared"
	cfgloader "github.com/paclabsnet/PortcullisMCP/internal/shared/config"
	identity "github.com/paclabsnet/PortcullisMCP/internal/shared/identity"
)

// signToken is a test helper that signs a JWT with the given key and kid.
func signToken(t *testing.T, key *rsa.PrivateKey, kid string, claims jwt.MapClaims) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = kid
	s, err := token.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// bigIntToBytes converts an int to a big-endian byte slice.
func bigIntToBytes(n int) []byte {
	return big.NewInt(int64(n)).Bytes()
}

func TestBuildIdentityNormalizer_EmptyNormalizerReturnsError(t *testing.T) {
	_, err := buildIdentityNormalizer(&IdentityConfig{})
	if err == nil {
		t.Fatal("expected error for empty normalizer, got nil")
	}
}

func TestBuildIdentityNormalizer_Passthrough(t *testing.T) {
	cfg := IdentityConfig{Strategy: "passthrough"}
	_ = cfg.Validate()
	n, err := buildIdentityNormalizer(&cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := n.(*passthroughNormalizer); !ok {
		t.Errorf("expected *passthroughNormalizer, got %T", n)
	}
}

func TestBuildIdentityNormalizer_OIDCVerify(t *testing.T) {
	cfg := IdentityConfig{
		Strategy: "oidc-verify",
		Config: map[string]any{
			"issuer":   "https://idp.example.com",
			"jwks_url": "https://localhost",
		},
	}
	_ = cfg.Validate()
	n, err := buildIdentityNormalizer(&cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := n.(*oidcVerifyingNormalizer); !ok {
		t.Errorf("expected *oidcVerifyingNormalizer, got %T", n)
	}
}

func TestBuildIdentityNormalizer_OIDCVerifyMissingIssuer(t *testing.T) {
	cfg := IdentityConfig{
		Strategy: "oidc-verify",
		Config: map[string]any{
			"jwks_url": "https://localhost",
		},
	}
	_ = cfg.Validate()
	_, err := buildIdentityNormalizer(&cfg)
	if err == nil {
		t.Fatal("expected error when issuer is missing, got nil")
	}
}

func TestBuildIdentityNormalizer_OIDCVerifyMissingJWKS(t *testing.T) {
	cfg := IdentityConfig{
		Strategy: "oidc-verify",
		Config: map[string]any{
			"issuer": "https://localhost",
		},
	}
	_ = cfg.Validate()
	_, err := buildIdentityNormalizer(&cfg)
	if err == nil {
		t.Fatal("expected error when JWKS URL is missing, got nil")
	}
}

func TestBuildIdentityNormalizer_UnknownNormalizer(t *testing.T) {
	cfg := IdentityConfig{Strategy: "bogus"}
	_ = cfg.Validate()
	_, err := buildIdentityNormalizer(&cfg)
	if err == nil {
		t.Fatal("expected error for unknown normalizer, got nil")
	}
}

func TestNormalizeIdentity_HandleCallIntegration(t *testing.T) {
	pdp := &capturingPDP{}
	srv := &Server{
		normalizer:  &passthroughNormalizer{silenced: true},
		pdp:         pdp,
		router:      &mockRouter{callToolResult: &mcp.CallToolResult{}},
		workflow:    &mockWorkflow{requestID: "wf-1"},
		decisionLog: NewDecisionLogger(cfgloader.DecisionLogConfig{Enabled: false}),
	}

	req := shared.EnrichedMCPRequest{
		ServerName: "test-server",
		ToolName:   "test-tool",
		UserIdentity: shared.UserIdentity{
			UserID:     "alice",
			Groups:     []string{"admins"},
			SourceType: "os",
		},
		TraceID: "req-1",
	}
	body, _ := json.Marshal(req)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/call", bytes.NewReader(body))
	srv.handleCall(w, r)

	captured := pdp.lastReq.Principal
	if captured.UserID != "alice" {
		t.Errorf("PDP received UserID %q, want alice", captured.UserID)
	}
	if len(captured.Groups) != 1 || captured.Groups[0] != "admins" {
		t.Errorf("PDP received groups %v, want [admins]", captured.Groups)
	}
}

type capturingPDP struct {
	lastReq AuthorizedRequest
}

func (c *capturingPDP) Evaluate(_ context.Context, req AuthorizedRequest) (shared.PDPResponse, error) {
	c.lastReq = req
	return shared.PDPResponse{Decision: "allow"}, nil
}

func newOIDCNormalizerWithJWKS(t *testing.T, maxAgeSecs int) (*oidcVerifyingNormalizer, *rsa.PrivateKey, string, string) {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	kid := "test-kid"
	issuer := "https://idp.example.com"

	jwksSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := base64.RawURLEncoding.EncodeToString(privateKey.N.Bytes())
		e := base64.RawURLEncoding.EncodeToString(bigIntToBytes(privateKey.E))
		_ = json.NewEncoder(w).Encode(jwks{Keys: []jwk{{Kid: kid, Kty: "RSA", Alg: "RS256", N: n, E: e}}})
	}))
	t.Cleanup(jwksSrv.Close)

	n := &oidcVerifyingNormalizer{
		issuer:          issuer,
		jwksURL:         jwksSrv.URL,
		httpClient:      &http.Client{},
		maxTokenAgeSecs: maxAgeSecs,
	}
	return n, privateKey, kid, issuer
}

func TestOIDCVerifyingNormalizer_MaxTokenAge_WithinLimit(t *testing.T) {
	n, key, kid, issuer := newOIDCNormalizerWithJWKS(t, 300)

	raw := signToken(t, key, kid, jwt.MapClaims{
		"iss": issuer,
		"sub": "alice",
		"exp": time.Now().Add(1 * time.Hour).Unix(),
		"iat": time.Now().Add(-30 * time.Second).Unix(),
	})
	id := shared.UserIdentity{SourceType: "oidc", RawToken: raw}

	if _, err := n.Normalize(context.Background(), id); err != nil {
		t.Errorf("expected no error for token within max age, got: %v", err)
	}
}

func TestOIDCVerifyingNormalizer_MaxTokenAge_Exceeded(t *testing.T) {
	n, key, kid, issuer := newOIDCNormalizerWithJWKS(t, 60)

	raw := signToken(t, key, kid, jwt.MapClaims{
		"iss": issuer,
		"sub": "alice",
		"exp": time.Now().Add(1 * time.Hour).Unix(),
		"iat": time.Now().Add(-5 * time.Minute).Unix(),
	})
	id := shared.UserIdentity{SourceType: "oidc", RawToken: raw}

	_, err := n.Normalize(context.Background(), id)
	if err == nil {
		t.Fatal("expected error for token exceeding max age, got nil")
	}
	if !strings.Contains(err.Error(), "exceeds max allowed age") {
		t.Errorf("error should mention max allowed age, got: %v", err)
	}
}

func TestOIDCVerifyingNormalizer_MaxTokenAge_MissingIAT_FailsClosed(t *testing.T) {
	n, key, kid, issuer := newOIDCNormalizerWithJWKS(t, 300)

	raw := signToken(t, key, kid, jwt.MapClaims{
		"iss": issuer,
		"sub": "alice",
		"exp": time.Now().Add(1 * time.Hour).Unix(),
	})
	id := shared.UserIdentity{SourceType: "oidc", RawToken: raw}

	_, err := n.Normalize(context.Background(), id)
	if err == nil {
		t.Fatal("expected error when iat is missing and max_token_age_secs is configured, got nil")
	}
	if !strings.Contains(err.Error(), "iat claim") {
		t.Errorf("error should mention iat claim, got: %v", err)
	}
}

func TestOIDCVerifyingNormalizer_MaxTokenAge_Zero_MissingIATAllowed(t *testing.T) {
	n, key, kid, issuer := newOIDCNormalizerWithJWKS(t, 0)

	raw := signToken(t, key, kid, jwt.MapClaims{
		"iss": issuer,
		"sub": "alice",
		"exp": time.Now().Add(1 * time.Hour).Unix(),
	})
	id := shared.UserIdentity{SourceType: "oidc", RawToken: raw}

	if _, err := n.Normalize(context.Background(), id); err != nil {
		t.Errorf("expected no error when max_token_age_secs is 0 and iat is absent, got: %v", err)
	}
}

func TestOIDCVerifyingNormalizer_PreferredUsernameAndACR(t *testing.T) {
	tests := []struct {
		name              string
		claims            jwt.MapClaims
		wantPreferred     string
		wantACR           string
	}{
		{
			name: "both claims present",
			claims: jwt.MapClaims{
				"sub":                "00000000-0000-0000-0000-000000000001",
				"preferred_username": "alice@corp.com",
				"acr":                "mfa",
			},
			wantPreferred: "alice@corp.com",
			wantACR:       "mfa",
		},
		{
			name: "only preferred_username present",
			claims: jwt.MapClaims{
				"sub":                "00000000-0000-0000-0000-000000000002",
				"preferred_username": "bob@corp.com",
			},
			wantPreferred: "bob@corp.com",
			wantACR:       "",
		},
		{
			name: "neither claim present",
			claims: jwt.MapClaims{
				"sub": "00000000-0000-0000-0000-000000000003",
			},
			wantPreferred: "",
			wantACR:       "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			n, key, kid, issuer := newOIDCNormalizerWithJWKS(t, 0)

			tc.claims["iss"] = issuer
			tc.claims["exp"] = time.Now().Add(time.Hour).Unix()
			raw := signToken(t, key, kid, tc.claims)

			id := shared.UserIdentity{SourceType: "oidc", RawToken: raw}
			got, err := n.Normalize(context.Background(), id)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got.PreferredUsername != tc.wantPreferred {
				t.Errorf("PreferredUsername = %q, want %q", got.PreferredUsername, tc.wantPreferred)
			}
			if got.ACR != tc.wantACR {
				t.Errorf("ACR = %q, want %q", got.ACR, tc.wantACR)
			}
		})
	}
}

func TestPassthroughNormalizer_PreferredUsernameAndACR(t *testing.T) {
	n := &passthroughNormalizer{silenced: true}
	id := shared.UserIdentity{
		UserID:            "alice",
		SourceType:        "oidc",
		PreferredUsername: "alice@corp.com",
		ACR:               "mfa",
	}
	got, err := n.Normalize(context.Background(), id)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.PreferredUsername != "alice@corp.com" {
		t.Errorf("PreferredUsername = %q, want alice@corp.com", got.PreferredUsername)
	}
	if got.ACR != "mfa" {
		t.Errorf("ACR = %q, want mfa", got.ACR)
	}
}

func TestRegisterNormalizer(t *testing.T) {
	name := "custom-test"
	identity.Register(name, func(cfg identity.NormalizerConfig) (identity.Normalizer, error) {
		return &passthroughNormalizer{silenced: true}, nil
	})

	cfg := IdentityConfig{Strategy: name}
	_ = cfg.Validate()
	n, err := buildIdentityNormalizer(&cfg)
	if err != nil {
		t.Fatalf("failed to build custom normalizer: %v", err)
	}
	if _, ok := n.(*passthroughNormalizer); !ok {
		t.Errorf("expected *passthroughNormalizer, got %T", n)
	}
}
