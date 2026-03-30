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
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/paclabsnet/PortcullisMCP/internal/shared"
)

// oidcIdentity returns a fully-populated OIDC-sourced identity for use in tests.
func oidcIdentity() shared.UserIdentity {
	return shared.UserIdentity{
		UserID:      "alice@corp.com",
		DisplayName: "Alice",
		Groups:      []string{"developers", "admins"},
		Roles:       []string{"deploy"},
		Department:  "Engineering",
		AuthMethod:  []string{"pwd", "mfa"},
		RawToken:    "eyJ...",
		SourceType:  "oidc",
	}
}

// osIdentity returns a fully-populated OS-sourced identity for use in tests.
func osIdentity() shared.UserIdentity {
	return shared.UserIdentity{
		UserID:      "alice",
		DisplayName: "Alice",
		Groups:      []string{"developers", "admins"},
		Roles:       []string{"deploy"},
		Department:  "Engineering",
		AuthMethod:  []string{"os"},
		RawToken:    "fake-token",
		SourceType:  "os",
	}
}

// signToken generates a signed JWT for testing using the provided RSA key and claims.
func signToken(t *testing.T, key *rsa.PrivateKey, kid string, claims jwt.MapClaims) string {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = kid
	tokenString, err := token.SignedString(key)
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}
	return tokenString
}

// --- passthroughNormalizer tests ---

func TestPassthroughNormalizer_AcceptsAll(t *testing.T) {
	n := &passthroughNormalizer{silenced: true}

	for _, id := range []shared.UserIdentity{oidcIdentity(), osIdentity()} {
		got, err := n.Normalize(context.Background(), id)
		if err != nil {
			t.Fatalf("unexpected error for %s: %v", id.SourceType, err)
		}
		if got.UserID != id.UserID || len(got.Groups) != len(id.Groups) {
			t.Errorf("passthrough should not modify identity; got %+v", got)
		}
	}
}

// --- oidcVerifyingNormalizer tests ---

func TestOIDCVerifyingNormalizer_ValidToken(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	kid := "test-kid"
	issuer := "https://idp.example.com"
	
	jwksHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := base64.RawURLEncoding.EncodeToString(privateKey.N.Bytes())
		e := base64.RawURLEncoding.EncodeToString(bigIntToBytes(privateKey.E))
		keys := jwks{
			Keys: []jwk{
				{Kid: kid, Kty: "RSA", Alg: "RS256", N: n, E: e},
			},
		}
		json.NewEncoder(w).Encode(keys)
	})
	server := httptest.NewServer(jwksHandler)
	defer server.Close()

	exp := time.Now().Add(time.Hour).Truncate(time.Second)
	claims := jwt.MapClaims{
		"iss":    issuer,
		"sub":    "alice@corp.com",
		"exp":    exp.Unix(),
		"name":   "Alice",
		"groups": []any{"devs"},
	}
	raw := signToken(t, privateKey, kid, claims)

	n := &oidcVerifyingNormalizer{
		issuer:     issuer,
		jwksURL:    server.URL,
		httpClient: &http.Client{},
	}
	id := shared.UserIdentity{
		UserID:     "alice@corp.com",
		SourceType: "oidc",
		RawToken:   raw,
	}

	got, err := n.Normalize(context.Background(), id)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.UserID != "alice@corp.com" {
		t.Errorf("UserID = %q, want alice@corp.com", got.UserID)
	}
	if got.DisplayName != "Alice" {
		t.Errorf("DisplayName = %q, want Alice", got.DisplayName)
	}
	if len(got.Groups) != 1 || got.Groups[0] != "devs" {
		t.Errorf("Groups = %v, want [devs]", got.Groups)
	}
	if got.TokenExpiry != exp.Unix() {
		t.Errorf("TokenExpiry = %d, want %d", got.TokenExpiry, exp.Unix())
	}
}

func TestOIDCVerifyingNormalizer_VerifiedSubjectOverridesClaim(t *testing.T) {
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	kid := "test-kid"
	issuer := "https://idp.example.com"
	verifiedSub := "verified-alice"

	jwksHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := base64.RawURLEncoding.EncodeToString(privateKey.N.Bytes())
		e := base64.RawURLEncoding.EncodeToString(bigIntToBytes(privateKey.E))
		json.NewEncoder(w).Encode(jwks{Keys: []jwk{{Kid: kid, Kty: "RSA", Alg: "RS256", N: n, E: e}}})
	})
	server := httptest.NewServer(jwksHandler)
	defer server.Close()

	// Token contains "verified-alice"
	claims := jwt.MapClaims{
		"iss": issuer,
		"sub": verifiedSub,
		"exp": time.Now().Add(time.Hour).Unix(),
	}
	raw := signToken(t, privateKey, kid, claims)

	n := &oidcVerifyingNormalizer{issuer: issuer, jwksURL: server.URL, httpClient: &http.Client{}}
	
	// Request claims to be "imposter-alice"
	id := shared.UserIdentity{
		UserID:     "imposter-alice",
		SourceType: "oidc",
		RawToken:   raw,
	}

	got, err := n.Normalize(context.Background(), id)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Result MUST be "verified-alice"
	if got.UserID != verifiedSub {
		t.Errorf("UserID = %q, want %q (verified sub)", got.UserID, verifiedSub)
	}
}

func TestOIDCVerifyingNormalizer_AudienceMismatch(t *testing.T) {
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	kid := "test-kid"
	issuer := "https://idp.example.com"
	
	jwksHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := base64.RawURLEncoding.EncodeToString(privateKey.N.Bytes())
		e := base64.RawURLEncoding.EncodeToString(bigIntToBytes(privateKey.E))
		json.NewEncoder(w).Encode(jwks{Keys: []jwk{{Kid: kid, Kty: "RSA", Alg: "RS256", N: n, E: e}}})
	})
	server := httptest.NewServer(jwksHandler)
	defer server.Close()

	claims := jwt.MapClaims{
		"iss": issuer,
		"sub": "alice",
		"aud": "wrong-audience",
		"exp": time.Now().Add(time.Hour).Unix(),
	}
	raw := signToken(t, privateKey, kid, claims)

	n := &oidcVerifyingNormalizer{
		issuer:     issuer,
		jwksURL:    server.URL,
		audiences:  []string{"expected-audience"},
		httpClient: &http.Client{},
	}
	id := shared.UserIdentity{SourceType: "oidc", RawToken: raw}

	_, err := n.Normalize(context.Background(), id)
	if err == nil {
		t.Fatal("expected error for audience mismatch, got nil")
	}
	if !strings.Contains(err.Error(), "audience mismatch") {
		t.Errorf("error = %q, want it to mention audience mismatch", err.Error())
	}
}

func TestOIDCVerifyingNormalizer_AudienceMatch(t *testing.T) {
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	kid := "test-kid"
	issuer := "https://idp.example.com"
	
	jwksHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := base64.RawURLEncoding.EncodeToString(privateKey.N.Bytes())
		e := base64.RawURLEncoding.EncodeToString(bigIntToBytes(privateKey.E))
		json.NewEncoder(w).Encode(jwks{Keys: []jwk{{Kid: kid, Kty: "RSA", Alg: "RS256", N: n, E: e}}})
	})
	server := httptest.NewServer(jwksHandler)
	defer server.Close()

	claims := jwt.MapClaims{
		"iss": issuer,
		"sub": "alice",
		"aud": []any{"other", "expected-audience"},
		"exp": time.Now().Add(time.Hour).Unix(),
	}
	raw := signToken(t, privateKey, kid, claims)

	n := &oidcVerifyingNormalizer{
		issuer:     issuer,
		jwksURL:    server.URL,
		audiences:  []string{"expected-audience"},
		httpClient: &http.Client{},
	}
	id := shared.UserIdentity{SourceType: "oidc", RawToken: raw}

	_, err := n.Normalize(context.Background(), id)
	if err != nil {
		t.Fatalf("unexpected error for audience match: %v", err)
	}
}

func TestOIDCVerifyingNormalizer_AllowMissingExpiry(t *testing.T) {
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	kid := "test-kid"
	issuer := "https://idp.example.com"
	
	jwksHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := base64.RawURLEncoding.EncodeToString(privateKey.N.Bytes())
		e := base64.RawURLEncoding.EncodeToString(bigIntToBytes(privateKey.E))
		json.NewEncoder(w).Encode(jwks{Keys: []jwk{{Kid: kid, Kty: "RSA", Alg: "RS256", N: n, E: e}}})
	})
	server := httptest.NewServer(jwksHandler)
	defer server.Close()

	// Token WITHOUT exp claim
	claims := jwt.MapClaims{
		"iss": issuer,
		"sub": "alice",
	}
	raw := signToken(t, privateKey, kid, claims)

	// 1. Rejected by default (fail secure)
	n1 := &oidcVerifyingNormalizer{issuer: issuer, jwksURL: server.URL, allowMissingExpiry: false, httpClient: &http.Client{}}
	id := shared.UserIdentity{SourceType: "oidc", RawToken: raw}
	_, err := n1.Normalize(context.Background(), id)
	if err == nil {
		t.Fatal("expected error for missing exp by default, got nil")
	}
	if !strings.Contains(err.Error(), "missing exp claim") {
		t.Errorf("error = %q, want it to mention missing exp claim", err.Error())
	}

	// 2. Acceptable when allowMissingExpiry=true
	n2 := &oidcVerifyingNormalizer{issuer: issuer, jwksURL: server.URL, allowMissingExpiry: true, httpClient: &http.Client{}}
	_, err = n2.Normalize(context.Background(), id)
	if err != nil {
		t.Errorf("expected no error when allowMissingExpiry=true, got %v", err)
	}
}

func TestOIDCVerifyingNormalizer_JWKSRefreshOnKidMiss(t *testing.T) {
	privateKey1, _ := rsa.GenerateKey(rand.Reader, 2048)
	privateKey2, _ := rsa.GenerateKey(rand.Reader, 2048)
	kid1 := "kid-1"
	kid2 := "kid-2"
	issuer := "https://idp.example.com"

	refreshCount := 0
	jwksHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		refreshCount++
		n1 := base64.RawURLEncoding.EncodeToString(privateKey1.N.Bytes())
		e1 := base64.RawURLEncoding.EncodeToString(bigIntToBytes(privateKey1.E))
		
		keys := []jwk{
			{Kid: kid1, Kty: "RSA", Alg: "RS256", N: n1, E: e1},
		}

		// On second refresh, add the new key
		if refreshCount > 1 {
			n2 := base64.RawURLEncoding.EncodeToString(privateKey2.N.Bytes())
			e2 := base64.RawURLEncoding.EncodeToString(bigIntToBytes(privateKey2.E))
			keys = append(keys, jwk{Kid: kid2, Kty: "RSA", Alg: "RS256", N: n2, E: e2})
		}

		json.NewEncoder(w).Encode(jwks{Keys: keys})
	})
	server := httptest.NewServer(jwksHandler)
	defer server.Close()

	n := &oidcVerifyingNormalizer{issuer: issuer, jwksURL: server.URL, httpClient: &http.Client{}}

	// 1. First call with kid1 should work and populate cache
	claims1 := jwt.MapClaims{"iss": issuer, "sub": "alice", "exp": time.Now().Add(time.Hour).Unix()}
	raw1 := signToken(t, privateKey1, kid1, claims1)
	_, err := n.Normalize(context.Background(), shared.UserIdentity{SourceType: "oidc", RawToken: raw1})
	if err != nil {
		t.Fatalf("first call failed: %v", err)
	}
	if refreshCount != 1 {
		t.Errorf("expected 1 refresh, got %d", refreshCount)
	}

	// 2. Call with kid2 should fail initially (not in cache), trigger refresh, and then succeed
	claims2 := jwt.MapClaims{"iss": issuer, "sub": "bob", "exp": time.Now().Add(time.Hour).Unix()}
	raw2 := signToken(t, privateKey2, kid2, claims2)
	_, err = n.Normalize(context.Background(), shared.UserIdentity{SourceType: "oidc", RawToken: raw2})
	if err != nil {
		t.Fatalf("second call failed after refresh: %v", err)
	}
	if refreshCount != 2 {
		t.Errorf("expected 2 refreshes after kid miss, got %d", refreshCount)
	}
}

func bigIntToBytes(i int) []byte {
	b := make([]byte, 4)
	b[0] = byte(i >> 24)
	b[1] = byte(i >> 16)
	b[2] = byte(i >> 8)
	b[3] = byte(i)
	// Strip leading zeros
	for len(b) > 0 && b[0] == 0 {
		b = b[1:]
	}
	return b
}

func TestOIDCVerifyingNormalizer_ExpiredToken(t *testing.T) {
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	kid := "test-kid"
	issuer := "https://idp.example.com"
	
	jwksHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := base64.RawURLEncoding.EncodeToString(privateKey.N.Bytes())
		e := base64.RawURLEncoding.EncodeToString(bigIntToBytes(privateKey.E))
		json.NewEncoder(w).Encode(jwks{Keys: []jwk{{Kid: kid, Kty: "RSA", Alg: "RS256", N: n, E: e}}})
	})
	server := httptest.NewServer(jwksHandler)
	defer server.Close()

	claims := jwt.MapClaims{
		"iss": issuer,
		"sub": "alice",
		"exp": time.Now().Add(-time.Hour).Unix(),
	}
	raw := signToken(t, privateKey, kid, claims)

	n := &oidcVerifyingNormalizer{issuer: issuer, jwksURL: server.URL, httpClient: &http.Client{}}
	id := shared.UserIdentity{SourceType: "oidc", RawToken: raw}

	_, err := n.Normalize(context.Background(), id)
	if err == nil {
		t.Fatal("expected error for expired token, got nil")
	}
	if !strings.Contains(err.Error(), "expired") {
		t.Errorf("error = %q, want it to mention expired", err.Error())
	}
}

func TestOIDCVerifyingNormalizer_WrongIssuer(t *testing.T) {
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	kid := "test-kid"
	
	jwksHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := base64.RawURLEncoding.EncodeToString(privateKey.N.Bytes())
		e := base64.RawURLEncoding.EncodeToString(bigIntToBytes(privateKey.E))
		json.NewEncoder(w).Encode(jwks{Keys: []jwk{{Kid: kid, Kty: "RSA", Alg: "RS256", N: n, E: e}}})
	})
	server := httptest.NewServer(jwksHandler)
	defer server.Close()

	claims := jwt.MapClaims{
		"iss": "https://attacker.example.com",
		"sub": "alice",
		"exp": time.Now().Add(time.Hour).Unix(),
	}
	raw := signToken(t, privateKey, kid, claims)

	n := &oidcVerifyingNormalizer{issuer: "https://idp.example.com", jwksURL: server.URL, httpClient: &http.Client{}}
	id := shared.UserIdentity{SourceType: "oidc", RawToken: raw}

	_, err := n.Normalize(context.Background(), id)
	if err == nil {
		t.Fatal("expected error for wrong issuer, got nil")
	}
}

func TestOIDCVerifyingNormalizer_OSStripsDirectoryClaims(t *testing.T) {
	n := &oidcVerifyingNormalizer{issuer: "https://idp.example.com", jwksURL: "http://localhost", httpClient: &http.Client{}}
	id := osIdentity()

	got, err := n.Normalize(context.Background(), id)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.UserID != id.UserID {
		t.Errorf("UserID = %q, want %q", got.UserID, id.UserID)
	}
	if len(got.Groups) != 0 {
		t.Errorf("oidc-verify strips OS groups, got %v", got.Groups)
	}
	if len(got.Roles) != 0 {
		t.Errorf("oidc-verify strips OS roles, got %v", got.Roles)
	}
}

// --- buildIdentityNormalizer factory tests ---

func TestBuildIdentityNormalizer_EmptyNormalizerReturnsError(t *testing.T) {
	_, err := buildIdentityNormalizer(IdentityConfig{})
	if err == nil {
		t.Fatal("expected error for empty normalizer, got nil")
	}
}

func TestBuildIdentityNormalizer_Passthrough(t *testing.T) {
	n, err := buildIdentityNormalizer(IdentityConfig{Normalizer: "passthrough"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := n.(*passthroughNormalizer); !ok {
		t.Errorf("expected *passthroughNormalizer, got %T", n)
	}
}

func TestBuildIdentityNormalizer_OIDCVerify(t *testing.T) {
	n, err := buildIdentityNormalizer(IdentityConfig{
		Normalizer: "oidc-verify",
		OIDCVerify: OIDCVerifyConfig{Issuer: "https://idp.example.com", JWKSURL: "http://localhost"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := n.(*oidcVerifyingNormalizer); !ok {
		t.Errorf("expected *oidcVerifyingNormalizer, got %T", n)
	}
}

func TestBuildIdentityNormalizer_OIDCVerifyMissingIssuer(t *testing.T) {
	_, err := buildIdentityNormalizer(IdentityConfig{Normalizer: "oidc-verify", OIDCVerify: OIDCVerifyConfig{JWKSURL: "http://localhost"}})
	if err == nil {
		t.Fatal("expected error when issuer is missing, got nil")
	}
}

func TestBuildIdentityNormalizer_OIDCVerifyMissingJWKS(t *testing.T) {
	_, err := buildIdentityNormalizer(IdentityConfig{Normalizer: "oidc-verify", OIDCVerify: OIDCVerifyConfig{Issuer: "http://localhost"}})
	if err == nil {
		t.Fatal("expected error when JWKS URL is missing, got nil")
	}
}

func TestBuildIdentityNormalizer_UnknownNormalizer(t *testing.T) {
	_, err := buildIdentityNormalizer(IdentityConfig{Normalizer: "bogus"})
	if err == nil {
		t.Fatal("expected error for unknown normalizer, got nil")
	}
}

// TestNormalizeIdentity_HandleCallIntegration verifies that identity
// normalization is applied by handleCall before the PDP sees the request.
func TestNormalizeIdentity_HandleCallIntegration(t *testing.T) {
	pdp := &capturingPDP{}
	srv := &Server{
		normalizer:  &passthroughNormalizer{silenced: true},
		pdp:         pdp,
		router:      &mockRouter{callToolResult: &mcp.CallToolResult{}},
		workflow:    &mockWorkflow{requestID: "wf-1"},
		decisionLog: NewDecisionLogger(DecisionLogConfig{}),
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

// capturingPDP records the last request it evaluated, for inspection in tests.
type capturingPDP struct {
	lastReq AuthorizedRequest
}

func (c *capturingPDP) Evaluate(_ context.Context, req AuthorizedRequest) (shared.PDPResponse, error) {
	c.lastReq = req
	return shared.PDPResponse{Decision: "allow"}, nil
}

// --- max_token_age_secs tests ---

// newOIDCNormalizerWithJWKS is a test helper that creates an oidcVerifyingNormalizer
// backed by a real JWKS server so we can exercise the full Normalize path.
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
		"iat": time.Now().Add(-30 * time.Second).Unix(), // 30s old, well within 300s limit
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
		"iat": time.Now().Add(-5 * time.Minute).Unix(), // 5m old, exceeds 60s limit
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

	// No iat claim — must be rejected when max_token_age_secs is configured.
	raw := signToken(t, key, kid, jwt.MapClaims{
		"iss": issuer,
		"sub": "alice",
		"exp": time.Now().Add(1 * time.Hour).Unix(),
		// iat intentionally absent
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
	// max_token_age_secs = 0 means no enforcement; missing iat must be silently accepted.
	n, key, kid, issuer := newOIDCNormalizerWithJWKS(t, 0)

	raw := signToken(t, key, kid, jwt.MapClaims{
		"iss": issuer,
		"sub": "alice",
		"exp": time.Now().Add(1 * time.Hour).Unix(),
		// iat intentionally absent
	})
	id := shared.UserIdentity{SourceType: "oidc", RawToken: raw}

	if _, err := n.Normalize(context.Background(), id); err != nil {
		t.Errorf("expected no error when max_token_age_secs is 0 and iat is absent, got: %v", err)
	}
}

// --- preferred_username / acr claim tests ---

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
	RegisterNormalizer(name, func(cfg IdentityConfig) (IdentityNormalizer, error) {
		return &passthroughNormalizer{silenced: true}, nil
	})

	n, err := buildIdentityNormalizer(IdentityConfig{Normalizer: name})
	if err != nil {
		t.Fatalf("failed to build custom normalizer: %v", err)
	}
	if _, ok := n.(*passthroughNormalizer); !ok {
		t.Errorf("expected *passthroughNormalizer, got %T", n)
	}
}
