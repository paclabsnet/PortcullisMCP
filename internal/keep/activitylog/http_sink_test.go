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

package activitylog

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	cfgloader "github.com/paclabsnet/PortcullisMCP/internal/shared/config"
)

func defaultHTTPSinkCfg(url string) cfgloader.HTTPActivitySinkConfig {
	cfg := cfgloader.HTTPActivitySinkConfig{
		URL:              url,
		Encoding:         "ndjson",
		BatchSize:        3,
		MaxQueuedBatches: 2,
		FlushIntervalMS:  200,
		TimeoutMS:        2000,
		MaxRetries:       1,
		RetryBackoffMS:   50,
		Auth:             cfgloader.HTTPActivityAuthConfig{Type: "none"},
	}
	return cfg
}

func TestHTTPBatchSink_NDJSON_Encoding(t *testing.T) {
	t.Parallel()
	var gotBody, gotCT string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var buf strings.Builder
		for {
			b := make([]byte, 512)
			n, err := r.Body.Read(b)
			buf.Write(b[:n])
			if err != nil {
				break
			}
		}
		gotBody = buf.String()
		gotCT = r.Header.Get("Content-Type")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := defaultHTTPSinkCfg(srv.URL)
	sink, err := NewHTTPBatchSink(cfg)
	if err != nil {
		t.Fatalf("NewHTTPBatchSink: %v", err)
	}
	_ = sink.Write([]byte(`{"event":"a"}`))
	_ = sink.Write([]byte(`{"event":"b"}`))
	_ = sink.Write([]byte(`{"event":"c"}`)) // triggers batch flush (size=3)
	time.Sleep(300 * time.Millisecond)      // let dispatcher finish
	_ = sink.Close()

	if gotCT != "application/x-ndjson" {
		t.Errorf("Content-Type: got %q, want application/x-ndjson", gotCT)
	}
	lines := strings.Split(strings.TrimSuffix(gotBody, "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("want 3 lines, got %d: %q", len(lines), gotBody)
	}
	if !strings.Contains(lines[0], `"event":"a"`) {
		t.Errorf("line 0: %q", lines[0])
	}
}

func TestHTTPBatchSink_JSONArray_Encoding(t *testing.T) {
	t.Parallel()
	var gotBody, gotCT string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, 4096)
		n, _ := r.Body.Read(buf)
		gotBody = string(buf[:n])
		gotCT = r.Header.Get("Content-Type")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := defaultHTTPSinkCfg(srv.URL)
	cfg.Encoding = "json_array"
	sink, err := NewHTTPBatchSink(cfg)
	if err != nil {
		t.Fatalf("NewHTTPBatchSink: %v", err)
	}
	_ = sink.Write([]byte(`{"event":"x"}`))
	_ = sink.Write([]byte(`{"event":"y"}`))
	_ = sink.Write([]byte(`{"event":"z"}`)) // triggers flush
	time.Sleep(300 * time.Millisecond)
	_ = sink.Close()

	if gotCT != "application/json" {
		t.Errorf("Content-Type: got %q, want application/json", gotCT)
	}
	var arr []map[string]any
	if err := json.Unmarshal([]byte(gotBody), &arr); err != nil {
		t.Fatalf("invalid JSON array: %v — body: %q", err, gotBody)
	}
	if len(arr) != 3 {
		t.Errorf("want 3 elements, got %d", len(arr))
	}
}

func TestHTTPBatchSink_AuthHeaders(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		authType    string
		token       string
		wantAuthHdr string
		customKey   string
		customVal   string
	}{
		{"splunk", "splunk", "splunk-tok-123", "Splunk splunk-tok-123", "", ""},
		{"bearer", "bearer", "secret-xyz", "Bearer secret-xyz", "", ""},
		{"custom header", "none", "", "", "X-Custom", "myval"},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var gotAuth, gotCustom string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotAuth = r.Header.Get("Authorization")
				if tc.customKey != "" {
					gotCustom = r.Header.Get(tc.customKey)
				}
				w.WriteHeader(http.StatusOK)
			}))
			defer srv.Close()

			cfg := defaultHTTPSinkCfg(srv.URL)
			cfg.Auth = cfgloader.HTTPActivityAuthConfig{Type: tc.authType, Token: tc.token}
			if tc.customKey != "" {
				cfg.Headers = map[string]string{tc.customKey: tc.customVal}
			}
			sink, _ := NewHTTPBatchSink(cfg)
			_ = sink.Write([]byte(`{"e":"1"}`))
			_ = sink.Write([]byte(`{"e":"2"}`))
			_ = sink.Write([]byte(`{"e":"3"}`))
			time.Sleep(300 * time.Millisecond)
			_ = sink.Close()

			if tc.wantAuthHdr != "" && gotAuth != tc.wantAuthHdr {
				t.Errorf("Authorization: got %q, want %q", gotAuth, tc.wantAuthHdr)
			}
			if tc.customKey != "" && gotCustom != tc.customVal {
				t.Errorf("%s: got %q, want %q", tc.customKey, gotCustom, tc.customVal)
			}
		})
	}
}

func TestHTTPBatchSink_BatchThreshold(t *testing.T) {
	t.Parallel()
	var requestCount atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := defaultHTTPSinkCfg(srv.URL)
	cfg.BatchSize = 3
	cfg.FlushIntervalMS = 5000 // long interval — ensure only batch threshold fires
	sink, _ := NewHTTPBatchSink(cfg)
	_ = sink.Write([]byte(`{"e":"1"}`))
	_ = sink.Write([]byte(`{"e":"2"}`))
	_ = sink.Write([]byte(`{"e":"3"}`)) // batch size reached; immediate dispatch
	time.Sleep(300 * time.Millisecond)
	_ = sink.Close()

	if got := requestCount.Load(); got != 1 {
		t.Errorf("expected 1 HTTP POST, got %d", got)
	}
}

func TestHTTPBatchSink_TickerFlush(t *testing.T) {
	t.Parallel()
	var requestCount atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := defaultHTTPSinkCfg(srv.URL)
	cfg.BatchSize = 100     // large — won't be hit
	cfg.FlushIntervalMS = 50 // small interval
	sink, _ := NewHTTPBatchSink(cfg)
	_ = sink.Write([]byte(`{"e":"partial"}`))
	time.Sleep(200 * time.Millisecond) // ticker should fire
	_ = sink.Close()

	if got := requestCount.Load(); got == 0 {
		t.Error("expected at least 1 HTTP POST from ticker, got 0")
	}
}

func TestHTTPBatchSink_NonRetryable4xx(t *testing.T) {
	t.Parallel()
	for _, code := range []int{401, 408, 429, 400, 403} {
		code := code
		t.Run(http.StatusText(code), func(t *testing.T) {
			t.Parallel()
			var requestCount atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requestCount.Add(1)
				w.WriteHeader(code)
			}))
			defer srv.Close()

			cfg := defaultHTTPSinkCfg(srv.URL)
			cfg.MaxRetries = 3
			cfg.RetryBackoffMS = 10
			sink, _ := NewHTTPBatchSink(cfg)
			_ = sink.Write([]byte(`{"e":"1"}`))
			_ = sink.Write([]byte(`{"e":"2"}`))
			_ = sink.Write([]byte(`{"e":"3"}`))
			time.Sleep(300 * time.Millisecond)
			_ = sink.Close()

			// Must be exactly 1 attempt — no retries for 4xx.
			if got := requestCount.Load(); got != 1 {
				t.Errorf("code %d: expected exactly 1 request (no retries), got %d", code, got)
			}
			if got := sink.Stats()["dropped_batches"]; got.(int64) != 1 {
				t.Errorf("code %d: expected dropped_batches=1, got %v", code, got)
			}
		})
	}
}

func TestHTTPBatchSink_TransientRetry(t *testing.T) {
	t.Parallel()
	var requestCount atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := requestCount.Add(1)
		if n <= 2 {
			w.WriteHeader(http.StatusServiceUnavailable)
		} else {
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer srv.Close()

	cfg := defaultHTTPSinkCfg(srv.URL)
	cfg.MaxRetries = 3
	cfg.RetryBackoffMS = 20
	sink, _ := NewHTTPBatchSink(cfg)
	_ = sink.Write([]byte(`{"e":"1"}`))
	_ = sink.Write([]byte(`{"e":"2"}`))
	_ = sink.Write([]byte(`{"e":"3"}`))
	time.Sleep(500 * time.Millisecond)
	_ = sink.Close()

	if got := requestCount.Load(); got != 3 {
		t.Errorf("expected 3 requests (2 fails + 1 success), got %d", got)
	}
	if got := sink.Stats()["dropped_batches"].(int64); got != 0 {
		t.Errorf("expected no dropped batches, got %d", got)
	}
	if got := sink.Stats()["exported_entries"].(int64); got != 3 {
		t.Errorf("expected 3 exported entries, got %d", got)
	}
}

func TestHTTPBatchSink_DispatcherQueueFull(t *testing.T) {
	t.Parallel()
	// Block the dispatcher by holding the server mutex.
	var mu sync.Mutex
	mu.Lock() // held until we release
	var requestCount atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount.Add(1)
		mu.Lock() //nolint:staticcheck
		defer mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := defaultHTTPSinkCfg(srv.URL)
	cfg.BatchSize = 1
	cfg.MaxQueuedBatches = 2
	cfg.FlushIntervalMS = 5000
	cfg.TimeoutMS = 500
	sink, _ := NewHTTPBatchSink(cfg)

	// Write enough entries to fill the dispatcher queue while it's blocked.
	// First batch goes to dispatcher (which blocks). Then 2 more fill the channel.
	// The 4th batch should be dropped.
	for i := 0; i < 5; i++ {
		start := time.Now()
		_ = sink.Write([]byte(`{"e":"x"}`))
		elapsed := time.Since(start)
		if elapsed > 50*time.Millisecond {
			t.Errorf("Write blocked for %v — must be non-blocking", elapsed)
		}
	}

	// Let the blocked dispatcher proceed.
	mu.Unlock()
	time.Sleep(400 * time.Millisecond)
	_ = sink.Close()

	dropped := sink.Stats()["dropped_batches"].(int64)
	if dropped == 0 {
		t.Error("expected some batches to be dropped when queue was full")
	}
}

func TestHTTPBatchSink_RedirectNotFollowed(t *testing.T) {
	t.Parallel()
	// finalSrv is the redirect target — it must never be reached.
	var finalHit atomic.Int32
	finalSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		finalHit.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer finalSrv.Close()

	// redirectSrv responds with 302 → finalSrv.
	redirectSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, finalSrv.URL, http.StatusFound)
	}))
	defer redirectSrv.Close()

	cfg := defaultHTTPSinkCfg(redirectSrv.URL)
	cfg.BatchSize = 1
	cfg.FlushIntervalMS = 5000
	sink, err := NewHTTPBatchSink(cfg)
	if err != nil {
		t.Fatalf("NewHTTPBatchSink: %v", err)
	}
	_ = sink.Write([]byte(`{"e":"x"}`))
	time.Sleep(300 * time.Millisecond)
	_ = sink.Close()

	if got := finalHit.Load(); got != 0 {
		t.Errorf("redirect target was reached %d time(s); redirects must not be followed", got)
	}
}

func TestHTTPBatchSink_ShutdownFlush(t *testing.T) {
	t.Parallel()
	var requestCount atomic.Int32
	var entryCount atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount.Add(1)
		buf := make([]byte, 4096)
		n, _ := r.Body.Read(buf)
		body := strings.TrimSuffix(string(buf[:n]), "\n")
		entryCount.Add(int32(len(strings.Split(body, "\n"))))
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := defaultHTTPSinkCfg(srv.URL)
	cfg.BatchSize = 100     // large; won't trigger during writes
	cfg.FlushIntervalMS = 5000 // long; won't fire
	sink, _ := NewHTTPBatchSink(cfg)
	_ = sink.Write([]byte(`{"e":"1"}`))
	_ = sink.Write([]byte(`{"e":"2"}`))
	_ = sink.Close() // should flush remaining 2 entries

	if got := requestCount.Load(); got != 1 {
		t.Errorf("expected 1 POST on close, got %d", got)
	}
	if got := entryCount.Load(); got != 2 {
		t.Errorf("expected 2 entries delivered, got %d", got)
	}
}
