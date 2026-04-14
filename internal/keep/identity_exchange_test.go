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
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// newTestExchangeClient builds an IdentityExchangeClient pointed at srv with the
// given cache TTL (0 = no caching).
func newTestExchangeClient(t *testing.T, srv *httptest.Server, cacheTTL time.Duration) *IdentityExchangeClient {
	t.Helper()
	httpClient := noRedirectHTTPClient()
	httpClient.Timeout = 5 * time.Second
	var cache IdentityExchangeCacher
	if cacheTTL > 0 {
		cache = NewIdentityExchangeCache(100)
	}
	return &IdentityExchangeClient{
		url:         srv.URL,
		headers:     nil,
		backendName: "test-backend",
		httpClient:  httpClient,
		cache:       cache,
		cacheTTL:    cacheTTL,
	}
}

// --- JSON response tests ---

func TestIdentityExchangeClient_Success_StringIdentity(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if body["token"] == "" {
			http.Error(w, "missing token", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"identity": "user-12345"})
	}))
	defer srv.Close()

	client := newTestExchangeClient(t, srv, 0)
	got, ok := client.Exchange(context.Background(), "raw-token")
	if !ok {
		t.Fatal("expected successful exchange")
	}
	if got.Str != "user-12345" {
		t.Fatalf("got Str=%q, want %q", got.Str, "user-12345")
	}
	if got.Structured != nil {
		t.Fatalf("expected Structured=nil for string identity, got %v", got.Structured)
	}
}

func TestIdentityExchangeClient_Success_ObjectIdentity(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"identity":{"id":"u1","dept":"eng"}}`))
	}))
	defer srv.Close()

	client := newTestExchangeClient(t, srv, 0)
	got, ok := client.Exchange(context.Background(), "raw-token")
	if !ok {
		t.Fatal("expected successful exchange")
	}
	// Structured must be set.
	obj, ok2 := got.Structured.(map[string]any)
	if !ok2 {
		t.Fatalf("expected Structured to be map[string]any, got %T", got.Structured)
	}
	if obj["id"] != "u1" {
		t.Fatalf("expected id=u1, got %q", obj["id"])
	}
	// Str should be the compact JSON serialisation.
	var roundTrip map[string]string
	if err := json.Unmarshal([]byte(got.Str), &roundTrip); err != nil {
		t.Fatalf("Str is not valid JSON: %q: %v", got.Str, err)
	}
}

func TestIdentityExchangeClient_Success_ArrayIdentity(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"identity":["role-a","role-b"]}`)
	}))
	defer srv.Close()

	client := newTestExchangeClient(t, srv, 0)
	got, ok := client.Exchange(context.Background(), "tok")
	if !ok {
		t.Fatal("expected success for array identity")
	}
	arr, ok2 := got.Structured.([]any)
	if !ok2 {
		t.Fatalf("expected Structured to be []any, got %T", got.Structured)
	}
	if len(arr) != 2 || arr[0] != "role-a" {
		t.Fatalf("unexpected array content: %v", arr)
	}
	// Str should be compact JSON.
	var strArr []string
	if err := json.Unmarshal([]byte(got.Str), &strArr); err != nil {
		t.Fatalf("Str is not valid JSON array: %q: %v", got.Str, err)
	}
}

// --- Non-JSON (text/XML) response tests ---

func TestIdentityExchangeClient_Success_PlainTextResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, "  alice@corp.example  ")
	}))
	defer srv.Close()

	client := newTestExchangeClient(t, srv, 0)
	got, ok := client.Exchange(context.Background(), "tok")
	if !ok {
		t.Fatal("expected success for plain-text response")
	}
	if got.Str != "alice@corp.example" {
		t.Fatalf("got Str=%q, want trimmed value", got.Str)
	}
	if got.Structured != nil {
		t.Fatal("expected Structured=nil for plain-text response")
	}
}

func TestIdentityExchangeClient_Success_XMLResponse(t *testing.T) {
	xmlBody := `<identity><user>alice</user><dept>eng</dept></identity>`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		fmt.Fprint(w, xmlBody)
	}))
	defer srv.Close()

	client := newTestExchangeClient(t, srv, 0)
	got, ok := client.Exchange(context.Background(), "tok")
	if !ok {
		t.Fatal("expected success for XML response")
	}
	if got.Str != xmlBody {
		t.Fatalf("got Str=%q, want %q", got.Str, xmlBody)
	}
	if got.Structured != nil {
		t.Fatal("expected Structured=nil for XML response")
	}
}

func TestIdentityExchangeClient_FailDegraded_BinaryResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Write([]byte{0x80, 0x81, 0x82, 0xff}) // invalid UTF-8
	}))
	defer srv.Close()

	client := newTestExchangeClient(t, srv, 0)
	_, ok := client.Exchange(context.Background(), "tok")
	if ok {
		t.Fatal("expected fail-degraded for binary (non-UTF-8) response")
	}
}

// --- Fail-degraded: JSON-specific cases ---

func TestIdentityExchangeClient_FailDegraded_Non2xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "upstream error", http.StatusBadGateway)
	}))
	defer srv.Close()

	client := newTestExchangeClient(t, srv, 0)
	_, ok := client.Exchange(context.Background(), "tok")
	if ok {
		t.Fatal("expected fail-degraded on non-2xx response")
	}
}

func TestIdentityExchangeClient_FailDegraded_InvalidJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `not json`)
	}))
	defer srv.Close()

	client := newTestExchangeClient(t, srv, 0)
	_, ok := client.Exchange(context.Background(), "tok")
	if ok {
		t.Fatal("expected fail-degraded on invalid JSON")
	}
}

func TestIdentityExchangeClient_FailDegraded_MissingIdentityField(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"other":"value"}`)
	}))
	defer srv.Close()

	client := newTestExchangeClient(t, srv, 0)
	_, ok := client.Exchange(context.Background(), "tok")
	if ok {
		t.Fatal("expected fail-degraded on missing identity field")
	}
}

func TestIdentityExchangeClient_FailDegraded_NullIdentityField(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"identity":null}`)
	}))
	defer srv.Close()

	client := newTestExchangeClient(t, srv, 0)
	_, ok := client.Exchange(context.Background(), "tok")
	if ok {
		t.Fatal("expected fail-degraded on null identity field")
	}
}

func TestIdentityExchangeClient_FailDegraded_EmptyStringIdentity(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"identity":"   "}`)
	}))
	defer srv.Close()

	client := newTestExchangeClient(t, srv, 0)
	_, ok := client.Exchange(context.Background(), "tok")
	if ok {
		t.Fatal("expected fail-degraded on whitespace-only identity string")
	}
}

func TestIdentityExchangeClient_FailDegraded_ResponseTooLarge(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Write a body larger than maxExchangeResponseBytes.
		large := strings.Repeat("x", maxExchangeResponseBytes+1)
		fmt.Fprintf(w, `{"identity":"%s"}`, large)
	}))
	defer srv.Close()

	client := newTestExchangeClient(t, srv, 0)
	_, ok := client.Exchange(context.Background(), "tok")
	if ok {
		t.Fatal("expected fail-degraded on oversized response")
	}
}

func TestIdentityExchangeClient_FailDegraded_ScalarIdentityTypes(t *testing.T) {
	for _, body := range []string{
		`{"identity":true}`,
		`{"identity":false}`,
		`{"identity":42}`,
		`{"identity":3.14}`,
	} {
		body := body
		t.Run(body, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				fmt.Fprint(w, body)
			}))
			defer srv.Close()

			client := newTestExchangeClient(t, srv, 0)
			_, ok := client.Exchange(context.Background(), "tok")
			if ok {
				t.Fatalf("expected fail-degraded for scalar identity type: %s", body)
			}
		})
	}
}

// --- Cache tests ---

func TestIdentityExchangeClient_CacheHit(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"identity": "cached-id"})
	}))
	defer srv.Close()

	client := newTestExchangeClient(t, srv, time.Hour)

	for i := 0; i < 3; i++ {
		got, ok := client.Exchange(context.Background(), "same-token")
		if !ok {
			t.Fatalf("call %d: expected success", i)
		}
		if got.Str != "cached-id" {
			t.Fatalf("call %d: got Str=%q, want %q", i, got.Str, "cached-id")
		}
	}

	if calls != 1 {
		t.Fatalf("expected 1 HTTP call (cache should serve subsequent hits), got %d", calls)
	}
}

func TestIdentityExchangeClient_CacheHit_StructuredIdentity(t *testing.T) {
	// Verify that structured (JSON object) identities survive a cache round-trip.
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"identity":{"uid":"u99","role":"admin"}}`)
	}))
	defer srv.Close()

	client := newTestExchangeClient(t, srv, time.Hour)

	for i := 0; i < 2; i++ {
		got, ok := client.Exchange(context.Background(), "same-token")
		if !ok {
			t.Fatalf("call %d: expected success", i)
		}
		m, ok2 := got.Structured.(map[string]any)
		if !ok2 {
			t.Fatalf("call %d: expected Structured to be map[string]any after cache round-trip, got %T", i, got.Structured)
		}
		if m["uid"] != "u99" {
			t.Fatalf("call %d: unexpected Structured content: %v", i, m)
		}
	}
	if calls != 1 {
		t.Fatalf("expected 1 HTTP call, got %d", calls)
	}
}

func TestIdentityExchangeClient_CacheIsolation(t *testing.T) {
	// Two different raw tokens must produce independent cache entries.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		json.NewDecoder(r.Body).Decode(&body)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"identity": "id-for-" + body["token"]})
	}))
	defer srv.Close()

	client := newTestExchangeClient(t, srv, time.Hour)

	got1, ok1 := client.Exchange(context.Background(), "token-A")
	got2, ok2 := client.Exchange(context.Background(), "token-B")

	if !ok1 || !ok2 {
		t.Fatal("expected both exchanges to succeed")
	}
	if got1.Str == got2.Str {
		t.Fatalf("expected distinct identities for different tokens, both got %q", got1.Str)
	}
}

// --- Custom headers ---

func TestIdentityExchangeClient_CustomHeaders(t *testing.T) {
	var receivedAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"identity":"ok"}`)
	}))
	defer srv.Close()

	httpClient := noRedirectHTTPClient()
	httpClient.Timeout = 5 * time.Second
	client := &IdentityExchangeClient{
		url:         srv.URL,
		headers:     map[string]string{"Authorization": "Bearer static-secret"},
		backendName: "test",
		httpClient:  httpClient,
	}

	_, ok := client.Exchange(context.Background(), "tok")
	if !ok {
		t.Fatal("expected success")
	}
	if receivedAuth != "Bearer static-secret" {
		t.Fatalf("expected Authorization header to be forwarded, got %q", receivedAuth)
	}
}

// --- effectiveExchangeTTL ---

func TestEffectiveExchangeTTL_NoJWT(t *testing.T) {
	ttl := effectiveExchangeTTL(10*time.Minute, "not-a-jwt")
	if ttl != 10*time.Minute {
		t.Fatalf("expected configured TTL for non-JWT token, got %v", ttl)
	}
}

func TestEffectiveExchangeTTL_JWTNoExp(t *testing.T) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": "user@example.com",
	})
	raw, _ := token.SignedString([]byte("secret"))

	ttl := effectiveExchangeTTL(10*time.Minute, raw)
	if ttl != 10*time.Minute {
		t.Fatalf("expected configured TTL when no exp claim, got %v", ttl)
	}
}

func TestEffectiveExchangeTTL_JWTExpCapsTTL(t *testing.T) {
	expiry := time.Now().Add(2 * time.Minute)
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": "user@example.com",
		"exp": expiry.Unix(),
	})
	raw, _ := token.SignedString([]byte("secret"))

	ttl := effectiveExchangeTTL(10*time.Minute, raw)
	if ttl >= 10*time.Minute {
		t.Fatalf("expected TTL capped below 10m, got %v", ttl)
	}
	if ttl <= 0 {
		t.Fatalf("expected positive TTL, got %v", ttl)
	}
}

func TestEffectiveExchangeTTL_JWTConfiguredTTLShorter(t *testing.T) {
	expiry := time.Now().Add(10 * time.Minute)
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": "user@example.com",
		"exp": expiry.Unix(),
	})
	raw, _ := token.SignedString([]byte("secret"))

	ttl := effectiveExchangeTTL(2*time.Minute, raw)
	if ttl > 2*time.Minute+time.Second {
		t.Fatalf("expected TTL <= 2m, got %v", ttl)
	}
	if ttl <= 0 {
		t.Fatalf("expected positive TTL, got %v", ttl)
	}
}

func TestEffectiveExchangeTTL_JWTAlreadyExpired(t *testing.T) {
	expiry := time.Now().Add(-1 * time.Minute)
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": "user@example.com",
		"exp": expiry.Unix(),
	})
	raw, _ := token.SignedString([]byte("secret"))

	ttl := effectiveExchangeTTL(10*time.Minute, raw)
	if ttl != 0 {
		t.Fatalf("expected TTL=0 for already-expired token, got %v", ttl)
	}
}
