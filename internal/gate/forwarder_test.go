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
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/paclabsnet/PortcullisMCP/internal/shared"
)

// newTestForwarder creates a Forwarder pointing at the given test server URL.
func newTestForwarder(t *testing.T, srv *httptest.Server) *Forwarder {
	t.Helper()
	f, err := NewForwarder(KeepConfig{Endpoint: srv.URL})
	if err != nil {
		t.Fatalf("NewForwarder: %v", err)
	}
	return f
}

// ---- buildTransport ---------------------------------------------------------

func TestBuildTransport_NoAuth(t *testing.T) {
	transport, err := buildTransport(KeepAuth{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if transport == nil {
		t.Fatal("expected non-nil transport")
	}
}

func TestBuildTransport_BearerAuth(t *testing.T) {
	// Bearer auth does not affect the transport itself (header is added per-request).
	transport, err := buildTransport(KeepAuth{Type: "bearer", Token: "my-token"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if transport == nil {
		t.Fatal("expected non-nil transport")
	}
}

func TestBuildTransport_MtlsMissingCert(t *testing.T) {
	_, err := buildTransport(KeepAuth{Type: "mtls", Cert: "", Key: ""})
	if err == nil {
		t.Fatal("expected error for mTLS with missing cert/key, got nil")
	}
}

func TestBuildTransport_MtlsMissingKey(t *testing.T) {
	_, err := buildTransport(KeepAuth{Type: "mtls", Cert: "/some/cert.pem", Key: ""})
	if err == nil {
		t.Fatal("expected error for mTLS with missing key, got nil")
	}
}

func TestBuildTransport_MtlsCertFileNotFound(t *testing.T) {
	_, err := buildTransport(KeepAuth{
		Type: "mtls",
		Cert: "/does/not/exist.crt",
		Key:  "/does/not/exist.key",
	})
	if err == nil {
		t.Fatal("expected error for nonexistent mTLS cert/key files, got nil")
	}
}

func TestBuildTransport_ServerCANotFound(t *testing.T) {
	_, err := buildTransport(KeepAuth{ServerCA: "/does/not/exist/ca.pem"})
	if err == nil {
		t.Fatal("expected error for nonexistent CA file, got nil")
	}
}

func TestBuildTransport_ServerCAInvalidPEM(t *testing.T) {
	dir := t.TempDir()
	caFile := filepath.Join(dir, "bad-ca.pem")
	os.WriteFile(caFile, []byte("this is not a valid PEM certificate"), 0644)

	_, err := buildTransport(KeepAuth{ServerCA: caFile})
	if err == nil {
		t.Fatal("expected error for invalid CA PEM data, got nil")
	}
}

func TestBuildTransport_ServerCAValid(t *testing.T) {
	// Generate a self-signed cert and write its PEM as a custom CA.
	_, certPEM, _ := generateSelfSignedCert(t)
	dir := t.TempDir()
	caFile := filepath.Join(dir, "ca.pem")
	os.WriteFile(caFile, certPEM, 0644)

	transport, err := buildTransport(KeepAuth{ServerCA: caFile})
	if err != nil {
		t.Fatalf("unexpected error with valid CA: %v", err)
	}
	if transport == nil {
		t.Fatal("expected non-nil transport")
	}
}

func TestBuildTransport_MtlsValid(t *testing.T) {
	// Generate a self-signed cert + key pair and write them to temp files.
	keyPEM, certPEM, _ := generateSelfSignedCert(t)
	dir := t.TempDir()
	certFile := filepath.Join(dir, "client.crt")
	keyFile := filepath.Join(dir, "client.key")
	os.WriteFile(certFile, certPEM, 0644)
	os.WriteFile(keyFile, keyPEM, 0600)

	transport, err := buildTransport(KeepAuth{
		Type: "mtls",
		Cert: certFile,
		Key:  keyFile,
	})
	if err != nil {
		t.Fatalf("unexpected error with valid mTLS keypair: %v", err)
	}
	if transport == nil {
		t.Fatal("expected non-nil transport")
	}
}

// ---- CallTool ---------------------------------------------------------------

func TestCallTool_Allow(t *testing.T) {
	expected := mcp.CallToolResult{
		Content: []mcp.Content{
			&mcp.TextContent{Text: "result text"},
		},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/call" {
			t.Errorf("path = %q, want /call", r.URL.Path)
		}
		if r.Method != http.MethodPost {
			t.Errorf("method = %q, want POST", r.Method)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(expected)
	}))
	defer srv.Close()

	f := newTestForwarder(t, srv)
	result, err := f.CallTool(context.Background(), shared.EnrichedMCPRequest{
		ToolName: "read_file",
		TraceID: "req-1",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Content) == 0 {
		t.Error("expected content in result")
	}
}

func TestCallTool_Deny(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]string{
			"error":    "user not in approved group",
			"trace_id": "keep-trace-deny",
		})
	}))
	defer srv.Close()

	f := newTestForwarder(t, srv)
	_, err := f.CallTool(context.Background(), shared.EnrichedMCPRequest{TraceID: "req-deny"})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	// DenyError must unwrap to ErrDenied so existing errors.Is checks work.
	if !errors.Is(err, shared.ErrDenied) {
		t.Errorf("error = %v (%T), want error wrapping ErrDenied", err, err)
	}
	var denyErr *shared.DenyError
	if !errors.As(err, &denyErr) {
		t.Fatalf("error = %T, want *shared.DenyError", err)
	}
	if denyErr.Reason != "user not in approved group" {
		t.Errorf("DenyError.Reason = %q, want \"user not in approved group\"", denyErr.Reason)
	}
	if denyErr.TraceID != "keep-trace-deny" {
		t.Errorf("DenyError.TraceID = %q, want \"keep-trace-deny\"", denyErr.TraceID)
	}
}

func TestCallTool_EscalationPending(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted)
		json.NewEncoder(w).Encode(map[string]string{
			"reason":             "manager approval required",
			"workflow_reference": "https://guard.example.com/approve?token=xyz",
		})
	}))
	defer srv.Close()

	f := newTestForwarder(t, srv)
	_, err := f.CallTool(context.Background(), shared.EnrichedMCPRequest{TraceID: "req-esc"})
	if err == nil {
		t.Fatal("expected error for escalation pending, got nil")
	}
	var escErr *shared.EscalationPendingError
	if !isEscalationPending(err, &escErr) {
		t.Fatalf("error = %v (%T), want *EscalationPendingError", err, err)
	}
	if escErr.Reason != "manager approval required" {
		t.Errorf("Reason = %q, want manager approval required", escErr.Reason)
	}
	if escErr.Reference != "https://guard.example.com/approve?token=xyz" {
		t.Errorf("Reference = %q, want approval URL", escErr.Reference)
	}
}

func TestCallTool_EscalationPending_WithJWT(t *testing.T) {
	// Verify that pending_jwt is decoded from the 202 body and propagated
	// in EscalationPendingError so Gate can build the approval URL.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted)
		json.NewEncoder(w).Encode(map[string]string{
			"reason":         "manager approval required",
			"escalation_jti": "test-jti-abc",
			"pending_jwt":    "header.payload.signature",
		})
	}))
	defer srv.Close()

	f := newTestForwarder(t, srv)
	_, err := f.CallTool(context.Background(), shared.EnrichedMCPRequest{TraceID: "req-esc-jwt"})
	if err == nil {
		t.Fatal("expected escalation error, got nil")
	}
	var escErr *shared.EscalationPendingError
	if !isEscalationPending(err, &escErr) {
		t.Fatalf("error = %T, want *EscalationPendingError", err)
	}
	if escErr.EscalationJTI != "test-jti-abc" {
		t.Errorf("EscalationJTI = %q, want test-jti-abc", escErr.EscalationJTI)
	}
	if escErr.PendingJWT != "header.payload.signature" {
		t.Errorf("PendingJWT = %q, want header.payload.signature", escErr.PendingJWT)
	}
}

func TestCallTool_EscalationPending_TraceIDDecoded(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted)
		json.NewEncoder(w).Encode(map[string]string{
			"reason":   "approval required",
			"trace_id": "keep-trace-esc-42",
		})
	}))
	defer srv.Close()

	f := newTestForwarder(t, srv)
	_, err := f.CallTool(context.Background(), shared.EnrichedMCPRequest{TraceID: "req-esc-42"})
	var escErr *shared.EscalationPendingError
	if !errors.As(err, &escErr) {
		t.Fatalf("error = %T, want *EscalationPendingError", err)
	}
	if escErr.TraceID != "keep-trace-esc-42" {
		t.Errorf("EscalationPendingError.TraceID = %q, want \"keep-trace-esc-42\"", escErr.TraceID)
	}
}

func TestCallTool_PDPUnavailable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	f := newTestForwarder(t, srv)
	_, err := f.CallTool(context.Background(), shared.EnrichedMCPRequest{TraceID: "req-503"})
	if err != shared.ErrPDPUnavailable {
		t.Errorf("error = %v, want ErrPDPUnavailable", err)
	}
}

func TestCallTool_UnexpectedStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "internal server error"})
	}))
	defer srv.Close()

	f := newTestForwarder(t, srv)
	_, err := f.CallTool(context.Background(), shared.EnrichedMCPRequest{TraceID: "req-500"})
	if err == nil {
		t.Fatal("expected error for 500 response, got nil")
	}
}

func TestCallTool_NetworkError(t *testing.T) {
	// Point at a port nothing is listening on.
	f, _ := NewForwarder(KeepConfig{Endpoint: "http://127.0.0.1:1"})
	_, err := f.CallTool(context.Background(), shared.EnrichedMCPRequest{TraceID: "req-net"})
	if err == nil {
		t.Fatal("expected network error, got nil")
	}
}

func TestCallTool_ContextCancelled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer srv.Close()

	f := newTestForwarder(t, srv)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := f.CallTool(ctx, shared.EnrichedMCPRequest{TraceID: "req-cancel"})
	if err == nil {
		t.Fatal("expected error from cancelled context, got nil")
	}
}

// ---- ListTools --------------------------------------------------------------

func TestListTools_Success(t *testing.T) {
	tools := []shared.AnnotatedTool{
		{ServerName: "filesystem", Tool: &mcp.Tool{Name: "read_file"}},
		{ServerName: "github", Tool: &mcp.Tool{Name: "list_repos"}},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/tools" {
			t.Errorf("path = %q, want /tools", r.URL.Path)
		}
		// Verify user identity was sent in the request body.
		var body struct {
			UserIdentity shared.UserIdentity `json:"user_identity"`
		}
		json.NewDecoder(r.Body).Decode(&body)
		if body.UserIdentity.UserID != "u@corp.com" {
			t.Errorf("request user_identity.user_id = %q, want u@corp.com", body.UserIdentity.UserID)
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(tools)
	}))
	defer srv.Close()

	f := newTestForwarder(t, srv)
	result, err := f.ListTools(context.Background(),
		shared.UserIdentity{UserID: "u@corp.com"},
		nil,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result) != 2 {
		t.Fatalf("got %d tools, want 2", len(result))
	}
	if result[0].ServerName != "filesystem" {
		t.Errorf("result[0].ServerName = %q, want filesystem", result[0].ServerName)
	}
}

func TestListTools_WithEscalationTokens(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			EscalationTokens []shared.EscalationToken `json:"escalation_tokens"`
		}
		json.NewDecoder(r.Body).Decode(&body)
		if len(body.EscalationTokens) != 1 || body.EscalationTokens[0].TokenID != "tok-1" {
			t.Errorf("escalation tokens not forwarded correctly: %v", body.EscalationTokens)
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode([]shared.AnnotatedTool{})
	}))
	defer srv.Close()

	f := newTestForwarder(t, srv)
	tokens := []shared.EscalationToken{{TokenID: "tok-1", Raw: "raw"}}
	_, err := f.ListTools(context.Background(), shared.UserIdentity{}, tokens)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestListTools_EmptyResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode([]shared.AnnotatedTool{})
	}))
	defer srv.Close()

	f := newTestForwarder(t, srv)
	result, err := f.ListTools(context.Background(), shared.UserIdentity{}, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result) != 0 {
		t.Errorf("expected empty list, got %d tools", len(result))
	}
}

func TestListTools_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "internal"})
	}))
	defer srv.Close()

	f := newTestForwarder(t, srv)
	_, err := f.ListTools(context.Background(), shared.UserIdentity{}, nil)
	if err == nil {
		t.Fatal("expected error from server error response, got nil")
	}
}

// ---- SendLogs ---------------------------------------------------------------

func TestSendLogs_EmptyBatch(t *testing.T) {
	// Empty batch must not make any HTTP request.
	requestCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
	}))
	defer srv.Close()

	f := newTestForwarder(t, srv)
	if err := f.SendLogs(context.Background(), nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := f.SendLogs(context.Background(), []DecisionLogEntry{}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if requestCount != 0 {
		t.Errorf("empty batch should make 0 HTTP requests, made %d", requestCount)
	}
}

func TestSendLogs_Success(t *testing.T) {
	var receivedBatch struct {
		APIVersion string             `json:"api_version"`
		Entries    []DecisionLogEntry `json:"entries"`
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/log" {
			t.Errorf("path = %q, want /log", r.URL.Path)
		}
		json.NewDecoder(r.Body).Decode(&receivedBatch)
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]any{"status": "accepted", "count": 2})
	}))
	defer srv.Close()

	f := newTestForwarder(t, srv)
	entries := []DecisionLogEntry{
		{TraceID: "req-1", Decision: "allow", Source: "gate-fastpath"},
		{TraceID: "req-2", Decision: "deny", Source: "gate-fastpath"},
	}
	if err := f.SendLogs(context.Background(), entries); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if receivedBatch.APIVersion != shared.APIVersion {
		t.Errorf("api_version = %q, want %q", receivedBatch.APIVersion, shared.APIVersion)
	}
	if len(receivedBatch.Entries) != 2 {
		t.Errorf("server received %d entries, want 2", len(receivedBatch.Entries))
	}
}

func TestSendLogs_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "storage full"})
	}))
	defer srv.Close()

	f := newTestForwarder(t, srv)
	entries := []DecisionLogEntry{{TraceID: "req-1", Decision: "allow"}}
	err := f.SendLogs(context.Background(), entries)
	if err == nil {
		t.Fatal("expected error from server error response, got nil")
	}
}

// ---- Bearer token injection --------------------------------------------------

func TestPost_BearerTokenHeader(t *testing.T) {
	var authHeader string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]any{})
	}))
	defer srv.Close()

	f, _ := NewForwarder(KeepConfig{
		Endpoint: srv.URL,
		Auth:     KeepAuth{Type: "bearer", Token: "super-secret"},
	})
	f.ListTools(context.Background(), shared.UserIdentity{}, nil)

	if authHeader != "Bearer super-secret" {
		t.Errorf("Authorization = %q, want Bearer super-secret", authHeader)
	}
}

func TestPost_NoAuthHeaderWhenNotConfigured(t *testing.T) {
	var authHeader string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode([]shared.AnnotatedTool{})
	}))
	defer srv.Close()

	f := newTestForwarder(t, srv)
	f.ListTools(context.Background(), shared.UserIdentity{}, nil)

	if authHeader != "" {
		t.Errorf("expected no Authorization header, got %q", authHeader)
	}
}

func TestPost_ContentTypeJSON(t *testing.T) {
	var ct string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ct = r.Header.Get("Content-Type")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode([]shared.AnnotatedTool{})
	}))
	defer srv.Close()

	f := newTestForwarder(t, srv)
	f.ListTools(context.Background(), shared.UserIdentity{}, nil)

	if ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
}

// ---- helpers ----------------------------------------------------------------

// isEscalationPending checks whether err wraps *EscalationPendingError.
func isEscalationPending(err error, out **shared.EscalationPendingError) bool {
	if ep, ok := err.(*shared.EscalationPendingError); ok {
		*out = ep
		return true
	}
	return false
}

// generateSelfSignedCert creates an ephemeral ECDSA cert/key for transport tests.
// Returns keyPEM, certPEM, and the parsed *x509.Certificate.
func generateSelfSignedCert(t *testing.T) (keyPEM, certPEM []byte, cert *x509.Certificate) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	privDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal private key: %v", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privDER})

	parsed, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	// Make transport accept this self-signed cert.
	_ = tls.Certificate{}
	return keyPEM, certPEM, parsed
}
