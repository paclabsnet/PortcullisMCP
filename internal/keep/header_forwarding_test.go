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
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// --- headerInjectingRoundTripper ---

// makeRoundTripperTest starts an httptest server, returns the received header
// map from the first request, and a doRequest helper that makes a GET request
// through the provided RoundTripper with the given context.
func roundTripperTestServer(t *testing.T) (backend *httptest.Server, received *http.Header, mu *sync.Mutex) {
	t.Helper()
	mu = &sync.Mutex{}
	var hdr http.Header
	received = &hdr
	backend = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		*received = r.Header.Clone()
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(backend.Close)
	return backend, received, mu
}

func doRoundTrip(t *testing.T, rt http.RoundTripper, url string, ctx context.Context) {
	t.Helper()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	resp, err := (&http.Client{Transport: rt}).Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	resp.Body.Close()
}

func TestHeaderInjectingRoundTripper_NoClientHeaders(t *testing.T) {
	backend, received, mu := roundTripperTestServer(t)
	conn := &backendConn{}
	rt := &headerInjectingRoundTripper{conn: conn, inner: http.DefaultTransport}

	doRoundTrip(t, rt, backend.URL, context.Background())

	mu.Lock()
	defer mu.Unlock()
	if (*received).Get("Authorization") != "" {
		t.Error("no client headers in context: unexpected headers forwarded")
	}
}

func TestHeaderInjectingRoundTripper_DefaultForwarding(t *testing.T) {
	backend, received, mu := roundTripperTestServer(t)
	conn := &backendConn{} // ForwardHeaders empty → defaults to ["*"]
	rt := &headerInjectingRoundTripper{conn: conn, inner: http.DefaultTransport}

	ctx := withClientHeaders(context.Background(), map[string][]string{
		"Authorization": {"Bearer tok"},
		"X-Tenant-Id":   {"acme"},
	})
	doRoundTrip(t, rt, backend.URL, ctx)

	mu.Lock()
	defer mu.Unlock()
	if (*received).Get("Authorization") != "Bearer tok" {
		t.Errorf("Authorization not forwarded: %v", *received)
	}
	if (*received).Get("X-Tenant-Id") != "acme" {
		t.Errorf("X-Tenant-Id not forwarded: %v", *received)
	}
}

func TestHeaderInjectingRoundTripper_PrefixWildcard(t *testing.T) {
	backend, received, mu := roundTripperTestServer(t)
	conn := &backendConn{cfg: BackendConfig{ForwardHeaders: []string{"x-tenant-*"}}}
	rt := &headerInjectingRoundTripper{conn: conn, inner: http.DefaultTransport}

	ctx := withClientHeaders(context.Background(), map[string][]string{
		"X-Tenant-Id":     {"acme"},
		"X-Tenant-Region": {"us-east-1"},
		"Authorization":   {"Bearer tok"}, // not matched by x-tenant-*
	})
	doRoundTrip(t, rt, backend.URL, ctx)

	mu.Lock()
	defer mu.Unlock()
	if (*received).Get("X-Tenant-Id") != "acme" {
		t.Errorf("X-Tenant-Id should be forwarded via prefix wildcard")
	}
	if (*received).Get("X-Tenant-Region") != "us-east-1" {
		t.Errorf("X-Tenant-Region should be forwarded via prefix wildcard")
	}
	if (*received).Get("Authorization") != "" {
		t.Error("Authorization should not be forwarded (not matched by x-tenant-*)")
	}
}

func TestHeaderInjectingRoundTripper_DropHeaders(t *testing.T) {
	backend, received, mu := roundTripperTestServer(t)
	conn := &backendConn{cfg: BackendConfig{
		ForwardHeaders: []string{"*"},
		DropHeaders:    []string{"authorization"},
	}}
	rt := &headerInjectingRoundTripper{conn: conn, inner: http.DefaultTransport}

	ctx := withClientHeaders(context.Background(), map[string][]string{
		"Authorization": {"Bearer tok"},
		"X-Tenant-Id":   {"acme"},
	})
	doRoundTrip(t, rt, backend.URL, ctx)

	mu.Lock()
	defer mu.Unlock()
	if (*received).Get("Authorization") != "" {
		t.Error("Authorization should be blocked by drop_headers")
	}
	if (*received).Get("X-Tenant-Id") != "acme" {
		t.Errorf("X-Tenant-Id should still be forwarded: %v", *received)
	}
}

func TestHeaderInjectingRoundTripper_ForbiddenHeadersAlwaysStripped(t *testing.T) {
	backend, received, mu := roundTripperTestServer(t)
	// Even with ForwardHeaders: ["*"], forbidden headers must be stripped.
	conn := &backendConn{cfg: BackendConfig{ForwardHeaders: []string{"*"}}}
	rt := &headerInjectingRoundTripper{conn: conn, inner: http.DefaultTransport}

	ctx := withClientHeaders(context.Background(), map[string][]string{
		"Connection":      {"keep-alive"}, // forbidden hop-by-hop
		"Transfer-Encoding": {"chunked"},  // forbidden hop-by-hop
		"X-Tenant-Id":     {"acme"},
	})
	doRoundTrip(t, rt, backend.URL, ctx)

	mu.Lock()
	defer mu.Unlock()
	if (*received).Get("Connection") != "" {
		t.Error("Connection is a forbidden header and must not be forwarded")
	}
	if (*received).Get("Transfer-Encoding") != "" {
		t.Error("Transfer-Encoding is a forbidden header and must not be forwarded")
	}
	if (*received).Get("X-Tenant-Id") != "acme" {
		t.Errorf("X-Tenant-Id should be forwarded: %v", *received)
	}
}

func TestHeaderInjectingRoundTripper_Precedence_ForbiddenBeforeDrop(t *testing.T) {
	backend, received, mu := roundTripperTestServer(t)
	// Drop list includes "host", but forbidden check must fire first.
	conn := &backendConn{cfg: BackendConfig{
		ForwardHeaders: []string{"*"},
		DropHeaders:    []string{"host"}, // also forbidden
	}}
	rt := &headerInjectingRoundTripper{conn: conn, inner: http.DefaultTransport}

	ctx := withClientHeaders(context.Background(), map[string][]string{
		"Host":        {"example.com"},
		"X-Custom-Id": {"val"},
	})
	doRoundTrip(t, rt, backend.URL, ctx)

	mu.Lock()
	defer mu.Unlock()
	// Host must be absent — forbidden check fires before drop check.
	if (*received).Get("Host") == "example.com" {
		t.Error("Host is forbidden and must never be forwarded")
	}
	if (*received).Get("X-Custom-Id") != "val" {
		t.Errorf("X-Custom-Id should be forwarded: %v", *received)
	}
}

// TestHeaderInjectingRoundTripper_HotReload verifies that updating DropHeaders
// on the backendConn (simulating Router.Reload) takes effect on the next request
// without requiring a transport replacement.
func TestHeaderInjectingRoundTripper_HotReload(t *testing.T) {
	backend, received, mu := roundTripperTestServer(t)

	conn := &backendConn{cfg: BackendConfig{ForwardHeaders: []string{"*"}}}
	rt := &headerInjectingRoundTripper{conn: conn, inner: http.DefaultTransport}
	ctx := withClientHeaders(context.Background(), map[string][]string{
		"Authorization": {"Bearer tok"},
		"X-Tenant-Id":   {"acme"},
	})

	// First request: Authorization should be forwarded.
	doRoundTrip(t, rt, backend.URL, ctx)
	mu.Lock()
	if (*received).Get("Authorization") == "" {
		mu.Unlock()
		t.Fatal("pre-reload: Authorization should be forwarded")
	}
	mu.Unlock()

	// Simulate Router.Reload updating drop_headers.
	conn.cfgMu.Lock()
	conn.cfg.DropHeaders = []string{"authorization"}
	conn.cfgMu.Unlock()

	// Second request through the same transport: Authorization must now be blocked.
	doRoundTrip(t, rt, backend.URL, ctx)
	mu.Lock()
	defer mu.Unlock()
	if (*received).Get("Authorization") != "" {
		t.Error("post-reload: Authorization should be blocked by updated drop_headers")
	}
	if (*received).Get("X-Tenant-Id") != "acme" {
		t.Errorf("post-reload: X-Tenant-Id should still be forwarded: %v", *received)
	}
}

// --- identity header injection ---

func TestHeaderInjection_AddsIdentityHeader(t *testing.T) {
	backend, received, mu := roundTripperTestServer(t)
	conn := &backendConn{cfg: BackendConfig{IdentityHeader: "X-Identity-Token"}}
	rt := &headerInjectingRoundTripper{conn: conn, inner: http.DefaultTransport}

	ctx := withRawToken(context.Background(), "my-jwt-token")
	doRoundTrip(t, rt, backend.URL, ctx)

	mu.Lock()
	defer mu.Unlock()
	if got := (*received).Get("X-Identity-Token"); got != "my-jwt-token" {
		t.Errorf("X-Identity-Token = %q, want %q", got, "my-jwt-token")
	}
}

func TestHeaderInjection_OverridesForwardedHeader(t *testing.T) {
	backend, received, mu := roundTripperTestServer(t)
	conn := &backendConn{cfg: BackendConfig{
		ForwardHeaders: []string{"*"},
		IdentityHeader: "X-Identity-Token",
	}}
	rt := &headerInjectingRoundTripper{conn: conn, inner: http.DefaultTransport}

	// Client forwards a header with the same name — identity header must win.
	ctx := withClientHeaders(context.Background(), map[string][]string{
		"X-Identity-Token": {"client-supplied-value"},
	})
	ctx = withRawToken(ctx, "authoritative-token")
	doRoundTrip(t, rt, backend.URL, ctx)

	mu.Lock()
	defer mu.Unlock()
	if got := (*received).Get("X-Identity-Token"); got != "authoritative-token" {
		t.Errorf("X-Identity-Token = %q, want injected %q", got, "authoritative-token")
	}
}

func TestHeaderInjection_SkipsWhenNoRawToken(t *testing.T) {
	backend, received, mu := roundTripperTestServer(t)
	conn := &backendConn{cfg: BackendConfig{IdentityHeader: "X-Identity-Token"}}
	rt := &headerInjectingRoundTripper{conn: conn, inner: http.DefaultTransport}

	// No raw token in context — header must not be injected at all.
	doRoundTrip(t, rt, backend.URL, context.Background())

	mu.Lock()
	defer mu.Unlock()
	if got := (*received).Get("X-Identity-Token"); got != "" {
		t.Errorf("X-Identity-Token should be absent when no token in context, got %q", got)
	}
}

func TestHeaderInjection_SkipsWhenHeaderNotConfigured(t *testing.T) {
	backend, received, mu := roundTripperTestServer(t)
	conn := &backendConn{} // no IdentityHeader
	rt := &headerInjectingRoundTripper{conn: conn, inner: http.DefaultTransport}

	ctx := withRawToken(context.Background(), "some-token")
	doRoundTrip(t, rt, backend.URL, ctx)

	mu.Lock()
	defer mu.Unlock()
	// Token must not appear under any key.
	for name, vals := range *received {
		for _, v := range vals {
			if v == "some-token" {
				t.Errorf("token leaked into header %q: %q", name, v)
			}
		}
	}
}

// --- validateClientHeaders ---

func TestValidateClientHeaders_Valid(t *testing.T) {
	limits := LimitsConfig{}
	limits.ApplyDefaults()
	headers := map[string][]string{
		"Authorization": {"Bearer tok"},
		"X-Tenant-Id":   {"acme"},
	}
	if err := validateClientHeaders(headers, limits); err != nil {
		t.Errorf("valid headers rejected: %v", err)
	}
}

func TestValidateClientHeaders_Empty(t *testing.T) {
	limits := LimitsConfig{}
	limits.ApplyDefaults()
	if err := validateClientHeaders(nil, limits); err != nil {
		t.Errorf("nil headers should pass: %v", err)
	}
	if err := validateClientHeaders(map[string][]string{}, limits); err != nil {
		t.Errorf("empty headers should pass: %v", err)
	}
}

func TestValidateClientHeaders_TooManyHeaders(t *testing.T) {
	limits := LimitsConfig{MaxForwardedHeaders: 2}
	headers := map[string][]string{
		"X-A": {"1"},
		"X-B": {"2"},
		"X-C": {"3"},
	}
	if err := validateClientHeaders(headers, limits); err == nil {
		t.Error("expected error for too many headers, got nil")
	}
}

func TestValidateClientHeaders_HeaderNameTooLong(t *testing.T) {
	limits := LimitsConfig{MaxHeaderNameBytes: 10}
	headers := map[string][]string{
		"X-Very-Long-Header-Name": {"val"},
	}
	if err := validateClientHeaders(headers, limits); err == nil {
		t.Error("expected error for header name exceeding max, got nil")
	}
}

func TestValidateClientHeaders_HeaderValueTooLong(t *testing.T) {
	limits := LimitsConfig{MaxHeaderValueBytes: 5}
	headers := map[string][]string{
		"X-Short": {"this-value-is-too-long"},
	}
	if err := validateClientHeaders(headers, limits); err == nil {
		t.Error("expected error for header value exceeding max, got nil")
	}
}

func TestValidateClientHeaders_TotalBytesExceeded(t *testing.T) {
	limits := LimitsConfig{
		MaxHeaderNameBytes:            128,
		MaxHeaderValueBytes:           128,
		MaxForwardedHeadersTotalBytes: 20, // very small total
	}
	headers := map[string][]string{
		"X-Tenant-Id": {strings.Repeat("a", 15)}, // name(11) + value(15) = 26 > 20
	}
	if err := validateClientHeaders(headers, limits); err == nil {
		t.Error("expected error for total bytes exceeded, got nil")
	}
}

func TestValidateClientHeaders_ExactlyAtLimit(t *testing.T) {
	// Total = len("X-A") + len("v") = 4; limit = 4 → should pass.
	limits := LimitsConfig{
		MaxForwardedHeaders:           10,
		MaxHeaderNameBytes:            128,
		MaxHeaderValueBytes:           128,
		MaxForwardedHeadersTotalBytes: 4,
	}
	headers := map[string][]string{
		"X-A": {"v"},
	}
	if err := validateClientHeaders(headers, limits); err != nil {
		t.Errorf("headers exactly at limit should pass: %v", err)
	}
}
