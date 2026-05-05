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
	"errors"
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

func (c *capturingPDP) GetStaticPolicy(_ context.Context, _ string) (json.RawMessage, error) {
	return json.RawMessage("{}"), nil
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
		name          string
		claims        jwt.MapClaims
		wantPreferred string
		wantACR       string
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

// signHMAC signs a JWT with the given HMAC method and secret.
func signHMAC(t *testing.T, secret []byte, method jwt.SigningMethod, claims jwt.MapClaims) string {
	t.Helper()
	token := jwt.NewWithClaims(method, claims)
	s, err := token.SignedString(secret)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func newHMACNormalizer(method jwt.SigningMethod, secret []byte, opts ...func(*hmacVerifyingNormalizer)) *hmacVerifyingNormalizer {
	n := &hmacVerifyingNormalizer{method: method, secret: secret}
	for _, o := range opts {
		o(n)
	}
	return n
}

func TestHMACVerifyingNormalizer(t *testing.T) {
	secret := []byte("test-secret-at-least-256-bits-long-padding")
	issuer := "https://idp.example.com"
	future := time.Now().Add(1 * time.Hour).Unix()
	past := time.Now().Add(-1 * time.Hour).Unix()

	validClaims := jwt.MapClaims{
		"sub":    "alice@example.com",
		"email":  "alice@example.com",
		"name":   "Alice Admin",
		"groups": []any{"admin", "user"},
		"iss":    issuer,
		"aud":    []any{"portcullis-mcp"},
		"exp":    future,
		"iat":    time.Now().Add(-30 * time.Second).Unix(),
	}

	tests := []struct {
		name       string
		normalizer *hmacVerifyingNormalizer
		identity   shared.UserIdentity
		wantErr    string
		wantUserID string
		wantGroups []string
		wantEmail  string
	}{
		{
			name:       "valid HS256 token",
			normalizer: newHMACNormalizer(jwt.SigningMethodHS256, secret),
			identity: shared.UserIdentity{
				SourceType: "oidc",
				RawToken:   signHMAC(t, secret, jwt.SigningMethodHS256, validClaims),
			},
			wantUserID: "alice@example.com",
			wantGroups: []string{"admin", "user"},
			wantEmail:  "alice@example.com",
		},
		{
			name:       "valid HS384 token",
			normalizer: newHMACNormalizer(jwt.SigningMethodHS384, secret),
			identity: shared.UserIdentity{
				SourceType: "oidc",
				RawToken:   signHMAC(t, secret, jwt.SigningMethodHS384, validClaims),
			},
			wantUserID: "alice@example.com",
		},
		{
			name:       "valid HS512 token",
			normalizer: newHMACNormalizer(jwt.SigningMethodHS512, secret),
			identity: shared.UserIdentity{
				SourceType: "oidc",
				RawToken:   signHMAC(t, secret, jwt.SigningMethodHS512, validClaims),
			},
			wantUserID: "alice@example.com",
		},
		{
			name:       "hmac source type accepted",
			normalizer: newHMACNormalizer(jwt.SigningMethodHS256, secret),
			identity: shared.UserIdentity{
				SourceType: "hmac",
				RawToken:   signHMAC(t, secret, jwt.SigningMethodHS256, validClaims),
			},
			wantUserID: "alice@example.com",
		},
		{
			name:       "wrong secret",
			normalizer: newHMACNormalizer(jwt.SigningMethodHS256, secret),
			identity: shared.UserIdentity{
				SourceType: "oidc",
				RawToken:   signHMAC(t, []byte("wrong-secret"), jwt.SigningMethodHS256, validClaims),
			},
			wantErr: "verify hmac token",
		},
		{
			name:       "algorithm mismatch — HS512 token to HS256 normalizer",
			normalizer: newHMACNormalizer(jwt.SigningMethodHS256, secret),
			identity: shared.UserIdentity{
				SourceType: "oidc",
				RawToken:   signHMAC(t, secret, jwt.SigningMethodHS512, validClaims),
			},
			wantErr: "verify hmac token",
		},
		{
			name:       "RS256 token rejected by HMAC normalizer",
			normalizer: newHMACNormalizer(jwt.SigningMethodHS256, secret),
			identity: func() shared.UserIdentity {
				key, _ := rsa.GenerateKey(rand.Reader, 2048)
				raw := signToken(t, key, "kid", jwt.MapClaims{"sub": "alice", "exp": future, "iss": issuer})
				return shared.UserIdentity{SourceType: "oidc", RawToken: raw}
			}(),
			wantErr: "verify hmac token",
		},
		{
			name:       "expired token",
			normalizer: newHMACNormalizer(jwt.SigningMethodHS256, secret),
			identity: shared.UserIdentity{
				SourceType: "oidc",
				RawToken: signHMAC(t, secret, jwt.SigningMethodHS256, jwt.MapClaims{
					"sub": "alice@example.com",
					"iss": issuer,
					"exp": past,
					"iat": time.Now().Add(-2 * time.Hour).Unix(),
				}),
			},
			wantErr: "verify hmac token",
		},
		{
			name:       "missing exp rejected by default",
			normalizer: newHMACNormalizer(jwt.SigningMethodHS256, secret),
			identity: shared.UserIdentity{
				SourceType: "oidc",
				RawToken: signHMAC(t, secret, jwt.SigningMethodHS256, jwt.MapClaims{
					"sub": "alice@example.com",
					"iss": issuer,
					"iat": time.Now().Unix(),
				}),
			},
			wantErr: "missing exp claim",
		},
		{
			name: "missing exp allowed when allow_missing_expiry set",
			normalizer: newHMACNormalizer(jwt.SigningMethodHS256, secret, func(n *hmacVerifyingNormalizer) {
				n.allowMissingExpiry = true
			}),
			identity: shared.UserIdentity{
				SourceType: "oidc",
				RawToken: signHMAC(t, secret, jwt.SigningMethodHS256, jwt.MapClaims{
					"sub": "alice@example.com",
					"iss": issuer,
					"iat": time.Now().Unix(),
				}),
			},
			wantUserID: "alice@example.com",
		},
		{
			name: "issuer mismatch",
			normalizer: newHMACNormalizer(jwt.SigningMethodHS256, secret, func(n *hmacVerifyingNormalizer) {
				n.issuer = "https://expected.example.com"
			}),
			identity: shared.UserIdentity{
				SourceType: "oidc",
				RawToken: signHMAC(t, secret, jwt.SigningMethodHS256, jwt.MapClaims{
					"sub": "alice@example.com",
					"iss": "https://wrong.example.com",
					"exp": future,
				}),
			},
			wantErr: "does not match configured issuer",
		},
		{
			name: "audience mismatch",
			normalizer: newHMACNormalizer(jwt.SigningMethodHS256, secret, func(n *hmacVerifyingNormalizer) {
				n.audiences = []string{"portcullis-mcp"}
			}),
			identity: shared.UserIdentity{
				SourceType: "oidc",
				RawToken: signHMAC(t, secret, jwt.SigningMethodHS256, jwt.MapClaims{
					"sub": "alice@example.com",
					"iss": issuer,
					"aud": []any{"other-service"},
					"exp": future,
				}),
			},
			wantErr: "audience mismatch",
		},
		{
			name:       "missing sub rejected",
			normalizer: newHMACNormalizer(jwt.SigningMethodHS256, secret),
			identity: shared.UserIdentity{
				SourceType: "oidc",
				RawToken: signHMAC(t, secret, jwt.SigningMethodHS256, jwt.MapClaims{
					"iss": issuer,
					"exp": future,
				}),
			},
			wantErr: "missing sub claim",
		},
		{
			name: "token age exceeds max_token_age_secs",
			normalizer: newHMACNormalizer(jwt.SigningMethodHS256, secret, func(n *hmacVerifyingNormalizer) {
				n.maxTokenAgeSecs = 60
			}),
			identity: shared.UserIdentity{
				SourceType: "oidc",
				RawToken: signHMAC(t, secret, jwt.SigningMethodHS256, jwt.MapClaims{
					"sub": "alice@example.com",
					"iss": issuer,
					"exp": future,
					"iat": time.Now().Add(-5 * time.Minute).Unix(),
				}),
			},
			wantErr: "exceeds max allowed age",
		},
		{
			name:       "unexpected source type strips claims",
			normalizer: newHMACNormalizer(jwt.SigningMethodHS256, secret),
			identity: shared.UserIdentity{
				SourceType: "os",
				UserID:     "alice",
			},
			wantUserID: "alice",
		},
		{
			name:       "missing raw token",
			normalizer: newHMACNormalizer(jwt.SigningMethodHS256, secret),
			identity: shared.UserIdentity{
				SourceType: "oidc",
				RawToken:   "",
			},
			wantErr: "missing raw token",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.normalizer.Normalize(context.Background(), tc.identity)
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tc.wantErr)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Errorf("error = %q, want substring %q", err.Error(), tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tc.wantUserID != "" && got.UserID != tc.wantUserID {
				t.Errorf("UserID = %q, want %q", got.UserID, tc.wantUserID)
			}
			if tc.wantEmail != "" && got.Email != tc.wantEmail {
				t.Errorf("Email = %q, want %q", got.Email, tc.wantEmail)
			}
			if tc.wantGroups != nil {
				if len(got.Groups) != len(tc.wantGroups) {
					t.Errorf("Groups = %v, want %v", got.Groups, tc.wantGroups)
				} else {
					for i, g := range tc.wantGroups {
						if got.Groups[i] != g {
							t.Errorf("Groups[%d] = %q, want %q", i, got.Groups[i], g)
						}
					}
				}
			}
		})
	}
}

func TestBuildIdentityNormalizer_HMACVerify(t *testing.T) {
	cfg := IdentityConfig{
		Strategy: "hmac-verify",
		Config: map[string]any{
			"secret":    "a-test-secret-that-is-long-enough",
			"algorithm": "HS256",
		},
	}
	_ = cfg.Validate()
	n, err := buildIdentityNormalizer(&cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := n.(*hmacVerifyingNormalizer); !ok {
		t.Errorf("expected *hmacVerifyingNormalizer, got %T", n)
	}
}

// --- Webhook integration tests ---

// newWebhookNormalizer is a test helper that builds an OIDC normalizer wired to
// a test HTTP server acting as the normalization webhook.
func newWebhookNormalizer(t *testing.T, webhookSrv *httptest.Server, allowClaims, denyClaims []string, cacheTTL int) (*oidcVerifyingNormalizer, *rsa.PrivateKey, string, string) {
	t.Helper()
	n, key, kid, issuer := newOIDCNormalizerWithJWKS(t, 0)

	n.webhook = &NormalizationClient{
		endpoint:   webhookSrv.URL,
		maxBytes:   128 * 1024,
		httpClient: &http.Client{},
	}
	n.cache = NewPrincipalCache(100)
	n.normCfg = identity.NormalizerConfig{
		CacheTTL:        cacheTTL,
		MaxUserIDLength: 256,
	}
	n.allowClaims = allowClaims
	n.denyClaims = denyClaims
	return n, key, kid, issuer
}

func TestOIDCNormalizer_WebhookFlow_Success(t *testing.T) {
	want := shared.Principal{UserID: "alice-123", Email: "alice@corp.com", Groups: []string{"admins"}}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewEncoder(w).Encode(want); err != nil {
			t.Errorf("encode response: %v", err)
		}
	}))
	defer srv.Close()

	n, key, kid, issuer := newWebhookNormalizer(t, srv, nil, nil, 0)
	raw := signToken(t, key, kid, jwt.MapClaims{
		"iss": issuer,
		"sub": "alice-123",
		"exp": time.Now().Add(time.Hour).Unix(),
	})

	got, err := n.Normalize(context.Background(), shared.UserIdentity{SourceType: "oidc", RawToken: raw})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.UserID != want.UserID {
		t.Errorf("UserID = %q, want %q", got.UserID, want.UserID)
	}
	if got.Email != want.Email {
		t.Errorf("Email = %q, want %q", got.Email, want.Email)
	}
	if got.SourceType != "oidc" {
		t.Errorf("SourceType = %q, want oidc (should be set from verified token)", got.SourceType)
	}
}

func TestOIDCNormalizer_WebhookFlow_ClaimFilteringApplied(t *testing.T) {
	var receivedClaims map[string]any

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&receivedClaims)
		_ = json.NewEncoder(w).Encode(shared.Principal{UserID: "alice"})
	}))
	defer srv.Close()

	n, key, kid, issuer := newWebhookNormalizer(t, srv, []string{"sub", "iss"}, []string{"email"}, 0)
	raw := signToken(t, key, kid, jwt.MapClaims{
		"iss":   issuer,
		"sub":   "alice",
		"email": "alice@corp.com",
		"exp":   time.Now().Add(time.Hour).Unix(),
	})

	_, err := n.Normalize(context.Background(), shared.UserIdentity{SourceType: "oidc", RawToken: raw})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if _, ok := receivedClaims["sub"]; !ok {
		t.Error("expected 'sub' claim to be forwarded to webhook")
	}
	if _, ok := receivedClaims["email"]; ok {
		t.Error("'email' claim should be excluded by deny list")
	}
	if _, ok := receivedClaims["exp"]; ok {
		t.Error("'exp' claim should be excluded by allow list")
	}
}

func TestOIDCNormalizer_WebhookFlow_CacheHit(t *testing.T) {
	callCount := 0

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		_ = json.NewEncoder(w).Encode(shared.Principal{UserID: "alice"})
	}))
	defer srv.Close()

	n, key, kid, issuer := newWebhookNormalizer(t, srv, nil, nil, 600)
	raw := signToken(t, key, kid, jwt.MapClaims{
		"iss": issuer,
		"sub": "alice",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	id := shared.UserIdentity{SourceType: "oidc", RawToken: raw}

	if _, err := n.Normalize(context.Background(), id); err != nil {
		t.Fatalf("first call: %v", err)
	}
	if _, err := n.Normalize(context.Background(), id); err != nil {
		t.Fatalf("second call: %v", err)
	}

	if callCount != 1 {
		t.Errorf("webhook called %d times, want 1 (second call should be cache hit)", callCount)
	}
}

func TestOIDCNormalizer_WebhookFlow_CacheMissWhenTTLZero(t *testing.T) {
	callCount := 0

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		_ = json.NewEncoder(w).Encode(shared.Principal{UserID: "alice"})
	}))
	defer srv.Close()

	n, key, kid, issuer := newWebhookNormalizer(t, srv, nil, nil, 0) // TTL=0 disables caching
	raw := signToken(t, key, kid, jwt.MapClaims{
		"iss": issuer,
		"sub": "alice",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	id := shared.UserIdentity{SourceType: "oidc", RawToken: raw}

	if _, err := n.Normalize(context.Background(), id); err != nil {
		t.Fatalf("first call: %v", err)
	}
	if _, err := n.Normalize(context.Background(), id); err != nil {
		t.Fatalf("second call: %v", err)
	}

	if callCount != 2 {
		t.Errorf("webhook called %d times, want 2 (TTL=0 means no caching)", callCount)
	}
}

func TestOIDCNormalizer_WebhookFlow_ValidationFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Return a Principal with an empty user_id — should fail validation.
		_ = json.NewEncoder(w).Encode(shared.Principal{UserID: ""})
	}))
	defer srv.Close()

	n, key, kid, issuer := newWebhookNormalizer(t, srv, nil, nil, 0)
	raw := signToken(t, key, kid, jwt.MapClaims{
		"iss": issuer,
		"sub": "alice",
		"exp": time.Now().Add(time.Hour).Unix(),
	})

	_, err := n.Normalize(context.Background(), shared.UserIdentity{SourceType: "oidc", RawToken: raw})
	if err == nil {
		t.Fatal("expected validation error for empty user_id, got nil")
	}

	// Must be a NormalizationValidationError so server.go maps it to 403.
	var validErr *NormalizationValidationError
	if !errors.As(err, &validErr) {
		t.Errorf("expected *NormalizationValidationError, got %T: %v", err, err)
	}
	if !strings.Contains(err.Error(), "missing user_id") {
		t.Errorf("error = %q, want 'missing user_id'", err.Error())
	}
}

func TestOIDCNormalizer_WebhookFlow_WebhookError_FailsClosed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	n, key, kid, issuer := newWebhookNormalizer(t, srv, nil, nil, 0)
	raw := signToken(t, key, kid, jwt.MapClaims{
		"iss": issuer,
		"sub": "alice",
		"exp": time.Now().Add(time.Hour).Unix(),
	})

	_, err := n.Normalize(context.Background(), shared.UserIdentity{SourceType: "oidc", RawToken: raw})
	if err == nil {
		t.Fatal("expected error when webhook returns 500, got nil")
	}
}

func TestInitNormalizerWebhook_NoEndpoint_ReturnsOriginal(t *testing.T) {
	cfg := IdentityConfig{Strategy: "passthrough"}
	_ = cfg.Validate()
	base, err := buildIdentityNormalizer(&cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	peers := &PeersConfig{} // no normalization endpoint
	result, err := initNormalizerWebhook(context.Background(), base, peers, identity.NormalizerConfig{}, cfgloader.StorageConfig{}, "dev")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != base {
		t.Error("expected same normalizer instance when no endpoint configured")
	}
}

func TestInitNormalizerWebhook_ProductionHTTP_ReturnsError(t *testing.T) {
	cfg := IdentityConfig{Strategy: "passthrough"}
	_ = cfg.Validate()
	base, err := buildIdentityNormalizer(&cfg)
	if err != nil {
		t.Fatalf("build normalizer: %v", err)
	}
	peers := &PeersConfig{}
	peers.Normalization.Endpoint = "http://mapper.internal/map"
	_, err = initNormalizerWebhook(context.Background(), base, peers, identity.NormalizerConfig{}, cfgloader.StorageConfig{}, "production")
	if err == nil {
		t.Fatal("expected error for http:// endpoint in production mode, got nil")
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
