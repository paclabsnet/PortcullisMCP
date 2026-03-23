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

// --- strictNormalizer tests ---

func TestStrictNormalizer_OIDCPassesThrough(t *testing.T) {
	n := &strictNormalizer{}
	id := oidcIdentity()

	got, err := n.Normalize(context.Background(), id)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.UserID != id.UserID || len(got.Groups) != len(id.Groups) {
		t.Errorf("OIDC identity should pass through unchanged; got %+v", got)
	}
}

func TestStrictNormalizer_OSStripsDirectoryClaims(t *testing.T) {
	n := &strictNormalizer{}
	id := osIdentity()

	got, err := n.Normalize(context.Background(), id)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.UserID != id.UserID {
		t.Errorf("UserID = %q, want %q", got.UserID, id.UserID)
	}
	if got.SourceType != "os" {
		t.Errorf("SourceType = %q, want os", got.SourceType)
	}
	if len(got.Groups) != 0 {
		t.Errorf("Groups should be empty, got %v", got.Groups)
	}
	if len(got.Roles) != 0 {
		t.Errorf("Roles should be empty, got %v", got.Roles)
	}
	if got.Department != "" {
		t.Errorf("Department should be empty, got %q", got.Department)
	}
	if len(got.AuthMethod) != 0 {
		t.Errorf("AuthMethod should be empty, got %v", got.AuthMethod)
	}
	if got.DisplayName != "" {
		t.Errorf("DisplayName should be empty, got %q", got.DisplayName)
	}
}

func TestStrictNormalizer_OSStripsAllUnverifiedFields(t *testing.T) {
	n := &strictNormalizer{}
	id := osIdentity()
	// Ensure all fields are populated before stripping
	id.Email = "alice@example.com"
	id.Department = "Security"
	id.Roles = []string{"admin"}
	id.AuthMethod = []string{"password"}
	id.TokenExpiry = 123456789
	id.RawToken = "secret"

	got, err := n.Normalize(context.Background(), id)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// List of fields that MUST be stripped for "os" source
	if got.Email != "" {
		t.Errorf("Email should be stripped, got %q", got.Email)
	}
	if got.DisplayName != "" {
		t.Errorf("DisplayName should be stripped, got %q", got.DisplayName)
	}
	if len(got.Groups) != 0 {
		t.Errorf("Groups should be stripped, got %v", got.Groups)
	}
	if len(got.Roles) != 0 {
		t.Errorf("Roles should be stripped, got %v", got.Roles)
	}
	if got.Department != "" {
		t.Errorf("Department should be stripped, got %q", got.Department)
	}
	if len(got.AuthMethod) != 0 {
		t.Errorf("AuthMethod should be stripped, got %v", got.AuthMethod)
	}
	if got.TokenExpiry != 0 {
		t.Errorf("TokenExpiry should be stripped, got %d", got.TokenExpiry)
	}

	// Fields that MUST remain
	if got.UserID != "alice" {
		t.Errorf("UserID should remain, got %q", got.UserID)
	}
	if got.SourceType != "os" {
		t.Errorf("SourceType should remain, got %q", got.SourceType)
	}
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
		issuer:  issuer,
		jwksURL: server.URL,
		strict:  &strictNormalizer{},
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
	if got.UserID != id.UserID {
		t.Errorf("UserID = %q, want %q", got.UserID, id.UserID)
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

	n := &oidcVerifyingNormalizer{issuer: issuer, jwksURL: server.URL, strict: &strictNormalizer{}}
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

	n := &oidcVerifyingNormalizer{issuer: "https://idp.example.com", jwksURL: server.URL, strict: &strictNormalizer{}}
	id := shared.UserIdentity{SourceType: "oidc", RawToken: raw}

	_, err := n.Normalize(context.Background(), id)
	if err == nil {
		t.Fatal("expected error for wrong issuer, got nil")
	}
}

func TestOIDCVerifyingNormalizer_OSAppliesStrict(t *testing.T) {
	n := &oidcVerifyingNormalizer{issuer: "https://idp.example.com", jwksURL: "http://localhost", strict: &strictNormalizer{}}
	id := osIdentity()

	got, err := n.Normalize(context.Background(), id)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got.Groups) != 0 {
		t.Errorf("OS identity groups should be stripped by oidc-verify normalizer, got %v", got.Groups)
	}
}

// --- buildIdentityNormalizer factory tests ---

func TestBuildIdentityNormalizer_DefaultIsStrict(t *testing.T) {
	n, err := buildIdentityNormalizer(IdentityConfig{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := n.(*strictNormalizer); !ok {
		t.Errorf("expected *strictNormalizer, got %T", n)
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
		normalizer:  &strictNormalizer{},
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

	captured := pdp.lastPrincipal
	if len(captured.Groups) != 0 {
		t.Errorf("PDP received groups %v — strict normalizer should have stripped them", captured.Groups)
	}
	if captured.UserID != "alice" {
		t.Errorf("PDP received UserID %q, want alice", captured.UserID)
	}
}

// capturingPDP records the last request it evaluated, for inspection in tests.
type capturingPDP struct {
	lastReq       shared.EnrichedMCPRequest
	lastPrincipal shared.Principal
}

func (c *capturingPDP) Evaluate(_ context.Context, req shared.EnrichedMCPRequest, p shared.Principal) (shared.PDPResponse, error) {
	c.lastReq = req
	c.lastPrincipal = p
	return shared.PDPResponse{Decision: "allow"}, nil
}

func TestRegisterNormalizer(t *testing.T) {
	name := "custom-test"
	RegisterNormalizer(name, func(cfg IdentityConfig) (IdentityNormalizer, error) {
		return &strictNormalizer{}, nil
	})

	n, err := buildIdentityNormalizer(IdentityConfig{Normalizer: name})
	if err != nil {
		t.Fatalf("failed to build custom normalizer: %v", err)
	}
	if _, ok := n.(*strictNormalizer); !ok {
		t.Errorf("expected *strictNormalizer, got %T", n)
	}
}
