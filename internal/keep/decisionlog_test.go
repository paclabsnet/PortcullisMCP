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
	"compress/gzip"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestDecisionLogger_Disabled(t *testing.T) {
	dl := NewDecisionLogger(DecisionLogConfig{Enabled: false})

	// Log should be a no-op and must not panic.
	dl.Log(&DecisionLogEntry{RequestID: "req-1", Decision: "allow"})
	dl.Log(nil)

	if err := dl.Shutdown(); err != nil {
		t.Errorf("Shutdown returned error: %v", err)
	}

	stats := dl.Stats()
	if stats["enabled"] != false {
		t.Errorf("expected enabled=false, got %v", stats["enabled"])
	}
}

func TestDecisionLogger_Log_Nil(t *testing.T) {
	dl := NewDecisionLogger(DecisionLogConfig{
		Enabled:       true,
		BufferSize:    100,
		FlushInterval: 60,
		MaxBatchSize:  100,
	})
	defer dl.Shutdown()

	// nil entry must not panic or increment dropped count.
	dl.Log(nil)
}

func TestDecisionLogger_Log_SetsTimestamp(t *testing.T) {
	received := make(chan []*DecisionLogEntry, 1)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gz, err := gzip.NewReader(r.Body)
		if err != nil {
			t.Errorf("gzip reader: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		var entries []*DecisionLogEntry
		if err := json.NewDecoder(gz).Decode(&entries); err != nil {
			t.Errorf("decode entries: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		received <- entries
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	before := time.Now()
	dl := NewDecisionLogger(DecisionLogConfig{
		Enabled:       true,
		URL:           srv.URL,
		FlushInterval: 60, // long — rely on MaxBatchSize=1 to trigger immediate flush
		MaxBatchSize:  1,
		BufferSize:    100,
	})

	dl.Log(&DecisionLogEntry{RequestID: "req-1", Decision: "allow"})

	select {
	case entries := <-received:
		if len(entries) == 0 {
			t.Fatal("expected at least one entry from remote")
		}
		if entries[0].Timestamp.IsZero() {
			t.Error("Timestamp should be set automatically")
		}
		if entries[0].Timestamp.Before(before) {
			t.Error("Timestamp should be after test start")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for log entry to be flushed")
	}

	dl.Shutdown()
}

func TestDecisionLogger_PreserveExistingTimestamp(t *testing.T) {
	received := make(chan []*DecisionLogEntry, 1)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gz, _ := gzip.NewReader(r.Body)
		var entries []*DecisionLogEntry
		json.NewDecoder(gz).Decode(&entries)
		received <- entries
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	dl := NewDecisionLogger(DecisionLogConfig{
		Enabled:       true,
		URL:           srv.URL,
		FlushInterval: 60,
		MaxBatchSize:  1,
		BufferSize:    100,
	})

	fixed := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	dl.Log(&DecisionLogEntry{RequestID: "r", Decision: "deny", Timestamp: fixed})

	select {
	case entries := <-received:
		if len(entries) == 0 {
			t.Fatal("no entries received")
		}
		if !entries[0].Timestamp.Equal(fixed) {
			t.Errorf("Timestamp = %v, want pre-set %v", entries[0].Timestamp, fixed)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out")
	}

	dl.Shutdown()
}

func TestDecisionLogger_Shutdown_Flushes(t *testing.T) {
	received := make(chan []*DecisionLogEntry, 10)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gz, _ := gzip.NewReader(r.Body)
		var entries []*DecisionLogEntry
		json.NewDecoder(gz).Decode(&entries)
		received <- entries
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	dl := NewDecisionLogger(DecisionLogConfig{
		Enabled:       true,
		URL:           srv.URL,
		FlushInterval: 3600, // very long — entries flushed only on shutdown
		MaxBatchSize:  1000,
		BufferSize:    100,
	})

	dl.Log(&DecisionLogEntry{RequestID: "req-1", Decision: "allow"})
	dl.Log(&DecisionLogEntry{RequestID: "req-2", Decision: "deny"})

	dl.Shutdown()

	select {
	case entries := <-received:
		if len(entries) != 2 {
			t.Errorf("expected 2 entries flushed on shutdown, got %d", len(entries))
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for shutdown flush")
	}
}

func TestDecisionLogger_Shutdown_Idempotent(t *testing.T) {
	dl := NewDecisionLogger(DecisionLogConfig{Enabled: true, FlushInterval: 60, BufferSize: 100})

	if err := dl.Shutdown(); err != nil {
		t.Errorf("first Shutdown error: %v", err)
	}
	if err := dl.Shutdown(); err != nil {
		t.Errorf("second Shutdown error: %v", err)
	}
}

func TestDecisionLogger_RemoteError_NonBlocking(t *testing.T) {
	// Server always returns 500 — logger should not block or panic.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	dl := NewDecisionLogger(DecisionLogConfig{
		Enabled:       true,
		URL:           srv.URL,
		FlushInterval: 1,
		MaxBatchSize:  1,
		BufferSize:    100,
	})
	defer dl.Shutdown()

	// Log entries with a failing server; must not block.
	done := make(chan struct{})
	go func() {
		dl.Log(&DecisionLogEntry{RequestID: "req-1", Decision: "allow"})
		close(done)
	}()

	select {
	case <-done:
		// OK
	case <-time.After(3 * time.Second):
		t.Fatal("Log blocked when remote server returned error")
	}
}

func TestDecisionLogger_Stats(t *testing.T) {
	dl := NewDecisionLogger(DecisionLogConfig{
		Enabled:       true,
		URL:           "http://example.com/log",
		Console:       true,
		FlushInterval: 30,
		MaxBatchSize:  500,
		BufferSize:    1000,
	})
	defer dl.Shutdown()

	stats := dl.Stats()
	if stats["enabled"] != true {
		t.Errorf("enabled = %v, want true", stats["enabled"])
	}
	if stats["url"] != "http://example.com/log" {
		t.Errorf("url = %v, want http://example.com/log", stats["url"])
	}
	if stats["console"] != true {
		t.Errorf("console = %v, want true", stats["console"])
	}
	if stats["max_batch_size"] != 500 {
		t.Errorf("max_batch_size = %v, want 500", stats["max_batch_size"])
	}
}

func TestDecisionLogger_RequestHeaders(t *testing.T) {
	received := make(chan http.Header, 1)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received <- r.Header.Clone()
		// Drain body to avoid write errors.
		gz, _ := gzip.NewReader(r.Body)
		var entries []*DecisionLogEntry
		json.NewDecoder(gz).Decode(&entries)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	dl := NewDecisionLogger(DecisionLogConfig{
		Enabled:       true,
		URL:           srv.URL,
		FlushInterval: 60,
		MaxBatchSize:  1,
		BufferSize:    100,
		Headers: map[string]string{
			"X-API-Key": "my-key",
		},
	})

	dl.Log(&DecisionLogEntry{RequestID: "r", Decision: "allow"})

	select {
	case h := <-received:
		if h.Get("X-API-Key") != "my-key" {
			t.Errorf("X-API-Key = %q, want my-key", h.Get("X-API-Key"))
		}
		if h.Get("Content-Encoding") != "gzip" {
			t.Errorf("Content-Encoding = %q, want gzip", h.Get("Content-Encoding"))
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for request headers")
	}

	dl.Shutdown()
}
