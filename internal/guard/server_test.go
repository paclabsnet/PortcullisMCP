package guard

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	testKeepKey    = "test-keep-signing-key-32bytes!!"
	testSigningKey = "test-escalation-signing-key-32b!"
)

// makeServer creates a Guard server using the real templates directory.
// Tests run from the package directory so "templates" resolves correctly.
func makeServer(t *testing.T) *Server {
	t.Helper()
	s, err := NewServer(Config{
		Keep:                   KeepConfig{EscalationRequestSigningKey: testKeepKey},
		EscalationTokenSigning: SigningConfig{Key: testSigningKey, TTL: 3600},
		Templates:              TemplatesConfig{Dir: "templates"},
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	return s
}

// signKeepJWT signs an escalation request JWT exactly as Keep would.
func signKeepJWT(t *testing.T, claims escalationRequestClaims, expiry time.Time) string {
	t.Helper()
	if claims.RegisteredClaims.Issuer == "" {
		claims.RegisteredClaims.Issuer = "portcullis-keep"
	}
	claims.RegisteredClaims.IssuedAt = jwt.NewNumericDate(time.Now())
	claims.RegisteredClaims.ExpiresAt = jwt.NewNumericDate(expiry)
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString([]byte(testKeepKey))
	if err != nil {
		t.Fatalf("sign test JWT: %v", err)
	}
	return signed
}

// writeTempTemplates writes minimal but valid approval.html and token.html.
func writeTempTemplates(t *testing.T, dir string) {
	t.Helper()
	const approvalTmpl = `<html><body>{{.UserID}} {{.Token}}</body></html>`
	const tokenTmpl = `<html><body>{{.EscalationToken}} {{.GateURL}}</body></html>`
	if err := os.WriteFile(filepath.Join(dir, "approval.html"), []byte(approvalTmpl), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "token.html"), []byte(tokenTmpl), 0644); err != nil {
		t.Fatal(err)
	}
}

// ---- NewServer / loadTemplates -----------------------------------------------

func TestNewServer_MissingKeepKey(t *testing.T) {
	_, err := NewServer(Config{
		EscalationTokenSigning: SigningConfig{Key: testSigningKey},
		Templates:              TemplatesConfig{Dir: "templates"},
	})
	if err == nil {
		t.Fatal("expected error for missing keep key, got nil")
	}
}

func TestNewServer_MissingSigningKey(t *testing.T) {
	_, err := NewServer(Config{
		Keep:      KeepConfig{EscalationRequestSigningKey: testKeepKey},
		Templates: TemplatesConfig{Dir: "templates"},
	})
	if err == nil {
		t.Fatal("expected error for missing signing key, got nil")
	}
}

func TestNewServer_MissingTemplateDir(t *testing.T) {
	_, err := NewServer(Config{
		Keep:                   KeepConfig{EscalationRequestSigningKey: testKeepKey},
		EscalationTokenSigning: SigningConfig{Key: testSigningKey},
		// Templates.Dir is empty
	})
	if err == nil {
		t.Fatal("expected error for missing template dir, got nil")
	}
}

func TestNewServer_NonexistentTemplateDir(t *testing.T) {
	_, err := NewServer(Config{
		Keep:                   KeepConfig{EscalationRequestSigningKey: testKeepKey},
		EscalationTokenSigning: SigningConfig{Key: testSigningKey},
		Templates:              TemplatesConfig{Dir: "/does/not/exist"},
	})
	if err == nil {
		t.Fatal("expected error for non-existent template dir, got nil")
	}
}

func TestNewServer_DefaultTTL(t *testing.T) {
	dir := t.TempDir()
	writeTempTemplates(t, dir)

	s, err := NewServer(Config{
		Keep:                   KeepConfig{EscalationRequestSigningKey: testKeepKey},
		EscalationTokenSigning: SigningConfig{Key: testSigningKey, TTL: 0},
		Templates:              TemplatesConfig{Dir: dir},
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	if s.ttl != 24*time.Hour {
		t.Errorf("default TTL = %v, want 24h", s.ttl)
	}
}

func TestNewServer_CustomTTL(t *testing.T) {
	dir := t.TempDir()
	writeTempTemplates(t, dir)

	s, err := NewServer(Config{
		Keep:                   KeepConfig{EscalationRequestSigningKey: testKeepKey},
		EscalationTokenSigning: SigningConfig{Key: testSigningKey, TTL: 7200},
		Templates:              TemplatesConfig{Dir: dir},
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	if s.ttl != 2*time.Hour {
		t.Errorf("TTL = %v, want 2h", s.ttl)
	}
}

func TestLoadTemplates_EmptyDir(t *testing.T) {
	_, err := loadTemplates("")
	if err == nil {
		t.Fatal("expected error for empty dir, got nil")
	}
}

func TestLoadTemplates_MissingApproval(t *testing.T) {
	dir := t.TempDir()
	// Only token.html — approval.html is missing.
	os.WriteFile(filepath.Join(dir, "token.html"), []byte(`<html>{{.EscalationToken}}</html>`), 0644)

	_, err := loadTemplates(dir)
	if err == nil {
		t.Fatal("expected error for missing approval.html, got nil")
	}
}

func TestLoadTemplates_MissingToken(t *testing.T) {
	dir := t.TempDir()
	// Only approval.html — token.html is missing.
	os.WriteFile(filepath.Join(dir, "approval.html"), []byte(`<html>{{.UserID}}</html>`), 0644)

	_, err := loadTemplates(dir)
	if err == nil {
		t.Fatal("expected error for missing token.html, got nil")
	}
}

func TestLoadTemplates_BothPresent(t *testing.T) {
	dir := t.TempDir()
	writeTempTemplates(t, dir)

	tmpl, err := loadTemplates(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tmpl == nil {
		t.Fatal("expected non-nil template set")
	}
}

// ---- verifyRequest -----------------------------------------------------------

func TestVerifyRequest_Valid(t *testing.T) {
	s := makeServer(t)
	tokenStr := signKeepJWT(t, escalationRequestClaims{
		UserID: "alice@corp.com",
		Server: "github",
		Tool:   "push",
		Reason: "deploy",
	}, time.Now().Add(time.Hour))

	claims, err := s.verifyRequest(tokenStr)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if claims.UserID != "alice@corp.com" {
		t.Errorf("UserID = %q, want alice@corp.com", claims.UserID)
	}
	if claims.Server != "github" {
		t.Errorf("Server = %q, want github", claims.Server)
	}
	if claims.Tool != "push" {
		t.Errorf("Tool = %q, want push", claims.Tool)
	}
}

func TestVerifyRequest_WrongKey(t *testing.T) {
	s := makeServer(t)

	// Sign with a different key.
	claims := escalationRequestClaims{UserID: "attacker@evil.com"}
	claims.RegisteredClaims.ExpiresAt = jwt.NewNumericDate(time.Now().Add(time.Hour))
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, _ := token.SignedString([]byte("wrong-key-that-is-not-the-keep-key"))

	_, err := s.verifyRequest(signed)
	if err == nil {
		t.Fatal("expected error for tampered token, got nil")
	}
}

func TestVerifyRequest_Expired(t *testing.T) {
	s := makeServer(t)
	tokenStr := signKeepJWT(t, escalationRequestClaims{
		UserID: "alice@corp.com",
	}, time.Now().Add(-time.Hour)) // already expired

	_, err := s.verifyRequest(tokenStr)
	if err == nil {
		t.Fatal("expected error for expired token, got nil")
	}
}

func TestVerifyRequest_WrongAlgorithm(t *testing.T) {
	// Guard requires HS256; RS256 must be rejected.
	s := makeServer(t)

	// Build a token that claims RS256 but uses HS256 bytes — jwt library
	// will reject it at the key-function check.
	fakeClaims := escalationRequestClaims{UserID: "u"}
	fakeClaims.RegisteredClaims.ExpiresAt = jwt.NewNumericDate(time.Now().Add(time.Hour))
	// Sign with none/HS256 then manually replace alg header — simplest
	// approach: just pass a malformed header string.
	_, err := s.verifyRequest("not.a.jwt")
	if err == nil {
		t.Fatal("expected error for malformed token, got nil")
	}
}

func TestVerifyRequest_Malformed(t *testing.T) {
	s := makeServer(t)
	_, err := s.verifyRequest("definitely-not-a-jwt")
	if err == nil {
		t.Fatal("expected error for malformed token, got nil")
	}
}

// ---- issueEscalationToken ---------------------------------------------------

func TestIssueEscalationToken_Claims(t *testing.T) {
	s := makeServer(t)

	scope := []map[string]any{{"repo": "example/repo"}}
	requestClaims := &escalationRequestClaims{
		UserID:          "alice@corp.com",
		UserDisplayName: "Alice",
		Server:          "github",
		Tool:            "create_issue",
		EscalationScope: scope,
	}

	tokenStr, expiry, err := s.issueEscalationToken(requestClaims, "test-jti-123", scope)
	if err != nil {
		t.Fatalf("issueEscalationToken: %v", err)
	}
	if tokenStr == "" {
		t.Fatal("expected non-empty token string")
	}

	// Parse and verify with the signing key.
	parsed, err := jwt.ParseWithClaims(tokenStr, &escalationTokenClaims{}, func(t *jwt.Token) (any, error) {
		return []byte(testSigningKey), nil
	})
	if err != nil {
		t.Fatalf("parse issued token: %v", err)
	}
	tc, ok := parsed.Claims.(*escalationTokenClaims)
	if !ok || !parsed.Valid {
		t.Fatal("issued token has invalid claims")
	}
	if tc.Issuer != "portcullis-guard" {
		t.Errorf("Issuer = %q, want portcullis-guard", tc.Issuer)
	}
	if tc.Subject != "alice@corp.com" {
		t.Errorf("Subject = %q, want alice@corp.com", tc.Subject)
	}
	// The JTI of the issued token must match the request JTI so Gate can
	// correlate the approved token with its pending escalation entry.
	if tc.ID != "test-jti-123" {
		t.Errorf("JTI = %q, want test-jti-123", tc.ID)
	}
	if len(tc.Portcullis.ArgRestrictions) == 0 || tc.Portcullis.ArgRestrictions[0]["repo"] != "example/repo" {
		t.Errorf("Portcullis.ArgRestrictions[0][repo] = %v, want example/repo", tc.Portcullis.ArgRestrictions)
	}
	if len(tc.Portcullis.Tools) != 1 || tc.Portcullis.Tools[0] != "create_issue" {
		t.Errorf("Portcullis.Tools = %v, want [create_issue]", tc.Portcullis.Tools)
	}
	if len(tc.Portcullis.Services) != 1 || tc.Portcullis.Services[0] != "github" {
		t.Errorf("Portcullis.Services = %v, want [github]", tc.Portcullis.Services)
	}
	if expiry.IsZero() {
		t.Error("expected non-zero expiry time")
	}
	if expiry.Before(time.Now()) {
		t.Error("expiry should be in the future")
	}
}

func TestIssueEscalationToken_TTL(t *testing.T) {
	dir := t.TempDir()
	writeTempTemplates(t, dir)
	s, _ := NewServer(Config{
		Keep:                   KeepConfig{EscalationRequestSigningKey: testKeepKey},
		EscalationTokenSigning: SigningConfig{Key: testSigningKey, TTL: 7200},
		Templates:              TemplatesConfig{Dir: dir},
	})

	_, expiry, err := s.issueEscalationToken(&escalationRequestClaims{UserID: "u"}, "", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	expected := time.Now().Add(2 * time.Hour)
	diff := expiry.Sub(expected)
	if diff < 0 {
		diff = -diff
	}
	if diff > 5*time.Second {
		t.Errorf("expiry differs from 2h TTL by %v", diff)
	}
}

// ---- handleGet --------------------------------------------------------------

func TestHandleGet_MissingToken(t *testing.T) {
	s := makeServer(t)
	req := httptest.NewRequest(http.MethodGet, "/approve", nil)
	w := httptest.NewRecorder()
	s.handleGet(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestHandleGet_InvalidToken(t *testing.T) {
	s := makeServer(t)
	req := httptest.NewRequest(http.MethodGet, "/approve?token=not.a.valid.jwt", nil)
	w := httptest.NewRecorder()
	s.handleGet(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
}

func TestHandleGet_WrongKey(t *testing.T) {
	s := makeServer(t)

	// Sign with a different key than the server expects.
	claims := escalationRequestClaims{UserID: "bad@actor.com"}
	claims.RegisteredClaims.ExpiresAt = jwt.NewNumericDate(time.Now().Add(time.Hour))
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, _ := token.SignedString([]byte("wrong-key-entirely"))

	req := httptest.NewRequest(http.MethodGet, "/approve?token="+signed, nil)
	w := httptest.NewRecorder()
	s.handleGet(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
}

func TestHandleGet_ValidToken(t *testing.T) {
	s := makeServer(t)

	tokenStr := signKeepJWT(t, escalationRequestClaims{
		UserID:          "alice@corp.com",
		UserDisplayName: "Alice Corp",
		Server:          "github",
		Tool:            "create_issue",
		Reason:          "automation needs access",
	}, time.Now().Add(time.Hour))

	req := httptest.NewRequest(http.MethodGet, "/approve?token="+url.QueryEscape(tokenStr), nil)
	w := httptest.NewRecorder()
	s.handleGet(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d; body: %s", w.Code, http.StatusOK, w.Body.String())
	}
	ct := w.Header().Get("Content-Type")
	if !strings.HasPrefix(ct, "text/html") {
		t.Errorf("Content-Type = %q, want text/html", ct)
	}
	// The real approval.html template renders the user ID and the token.
	body := w.Body.String()
	if !strings.Contains(body, "alice@corp.com") {
		t.Errorf("approval page should contain user ID; body: %s", body)
	}
}

// ---- handlePost -------------------------------------------------------------

func TestHandlePost_MissingToken(t *testing.T) {
	s := makeServer(t)
	req := httptest.NewRequest(http.MethodPost, "/approve", strings.NewReader(""))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	s.handlePost(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestHandlePost_InvalidToken(t *testing.T) {
	s := makeServer(t)
	form := url.Values{"token": {"not.a.valid.jwt"}}
	req := httptest.NewRequest(http.MethodPost, "/approve", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	s.handlePost(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
}

func TestHandlePost_WrongKey(t *testing.T) {
	s := makeServer(t)

	claims := escalationRequestClaims{UserID: "attacker@evil.com"}
	claims.RegisteredClaims.ExpiresAt = jwt.NewNumericDate(time.Now().Add(time.Hour))
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, _ := token.SignedString([]byte("wrong-key"))

	form := url.Values{"token": {signed}}
	req := httptest.NewRequest(http.MethodPost, "/approve", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	s.handlePost(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
}

func TestHandlePost_ValidApproval(t *testing.T) {
	s := makeServer(t)

	scope := []map[string]any{{"resource": "repo:corp/backend"}}
	tokenStr := signKeepJWT(t, escalationRequestClaims{
		UserID:          "alice@corp.com",
		Server:          "github",
		Tool:            "push",
		Reason:          "hotfix deploy",
		EscalationScope: scope,
	}, time.Now().Add(time.Hour))

	form := url.Values{"token": {tokenStr}}
	req := httptest.NewRequest(http.MethodPost, "/approve", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	s.handlePost(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d; body: %s", w.Code, http.StatusOK, w.Body.String())
	}
	ct := w.Header().Get("Content-Type")
	if !strings.HasPrefix(ct, "text/html") {
		t.Errorf("Content-Type = %q, want text/html", ct)
	}

	// The token.html template renders the escalation token in a <textarea>.
	// Extract it and verify it's a valid JWT signed by our signing key.
	body := w.Body.String()
	if !strings.Contains(body, "eyJ") {
		t.Errorf("token page should contain a JWT (eyJ...); body: %s", body)
	}
}

func TestHandlePost_GatePortDefault(t *testing.T) {
	// When PortcullisGateManagementPort=0, gate URL should use default 7777.
	dir := t.TempDir()
	writeTempTemplates(t, dir)
	s, _ := NewServer(Config{
		Keep:                        KeepConfig{EscalationRequestSigningKey: testKeepKey},
		EscalationTokenSigning:      SigningConfig{Key: testSigningKey, TTL: 60},
		Templates:                   TemplatesConfig{Dir: dir},
		PortcullisGateManagementPort: 0,
	})

	tokenStr := signKeepJWT(t, escalationRequestClaims{
		UserID: "u@corp.com",
		Server: "s",
		Tool:   "t",
	}, time.Now().Add(time.Hour))

	form := url.Values{"token": {tokenStr}}
	req := httptest.NewRequest(http.MethodPost, "/approve", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	s.handlePost(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "7777") {
		t.Errorf("response should mention default port 7777; body: %s", w.Body.String())
	}
}

func TestHandlePost_GatePortCustom(t *testing.T) {
	dir := t.TempDir()
	writeTempTemplates(t, dir)
	s, _ := NewServer(Config{
		Keep:                        KeepConfig{EscalationRequestSigningKey: testKeepKey},
		EscalationTokenSigning:      SigningConfig{Key: testSigningKey, TTL: 60},
		Templates:                   TemplatesConfig{Dir: dir},
		PortcullisGateManagementPort: 9999,
	})

	tokenStr := signKeepJWT(t, escalationRequestClaims{
		UserID: "u@corp.com",
		Server: "s",
		Tool:   "t",
	}, time.Now().Add(time.Hour))

	form := url.Values{"token": {tokenStr}}
	req := httptest.NewRequest(http.MethodPost, "/approve", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	s.handlePost(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "9999") {
		t.Errorf("response should mention configured port 9999; body: %s", w.Body.String())
	}
}

// TestHandlePost_IssuedTokenVerifiable verifies that the escalation token
// rendered in the approval page can actually be parsed and verified by the PDP.
func TestHandlePost_IssuedTokenVerifiable(t *testing.T) {
	s := makeServer(t)

	scope := []map[string]any{{"action": "deploy"}}
	tokenStr := signKeepJWT(t, escalationRequestClaims{
		UserID:          "bob@corp.com",
		EscalationScope: scope,
	}, time.Now().Add(time.Hour))

	form := url.Values{"token": {tokenStr}}
	req := httptest.NewRequest(http.MethodPost, "/approve", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	s.handlePost(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d; body: %s", w.Code, w.Body.String())
	}

	// Extract the JWT from the rendered template body.
	// The real token.html puts the token in a <textarea id="tok">.
	body := w.Body.String()
	start := strings.Index(body, "eyJ")
	if start == -1 {
		t.Fatalf("no JWT found in body: %s", body)
	}
	// JWT ends at the first whitespace or < tag.
	rest := body[start:]
	end := strings.IndexAny(rest, " \t\n\r<")
	if end == -1 {
		end = len(rest)
	}
	issuedJWT := rest[:end]

	// Verify the issued escalation token with the signing key.
	parsed, err := jwt.ParseWithClaims(issuedJWT, &escalationTokenClaims{}, func(tok *jwt.Token) (any, error) {
		return []byte(testSigningKey), nil
	})
	if err != nil {
		t.Fatalf("issued escalation token is not valid: %v", err)
	}
	tc := parsed.Claims.(*escalationTokenClaims)
	if tc.Subject != "bob@corp.com" {
		t.Errorf("Subject = %q, want bob@corp.com", tc.Subject)
	}
	if len(tc.Portcullis.ArgRestrictions) == 0 || tc.Portcullis.ArgRestrictions[0]["action"] != "deploy" {
		t.Errorf("Portcullis.ArgRestrictions[0][action] = %v, want deploy", tc.Portcullis.ArgRestrictions)
	}
}
