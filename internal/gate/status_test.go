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
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// newGateForStatusTests builds a minimal *Gate with Keep and Guard endpoints
// configured, and optionally a degradedReason (translated to state machine).
func newGateForStatusTests(keepURL, guardURL, degradedReason string) *Gate {
	sm := NewStateMachine()
	if degradedReason != "" {
		sm.SetSystemError(SubstateInvalid, degradedReason, "")
	} else {
		sm.SetAuthenticated()
	}
	return &Gate{
		cfg: Config{
			Keep:  KeepConfig{Endpoint: keepURL},
			Guard: GuardConfig{EscalationApprovalEndpoint: guardURL},
		},
		stateMachine: sm,
	}
}

// healthzServer returns a test HTTP server that responds 200 to GET /healthz.
func healthzServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
}

// ---- pingHealth -------------------------------------------------------------

func TestPingHealth_Available(t *testing.T) {
	srv := healthzServer(t)
	defer srv.Close()

	result := pingHealth(context.Background(), srv.URL)
	if result != "available" {
		t.Errorf("pingHealth = %q, want %q", result, "available")
	}
}

func TestPingHealth_Unavailable(t *testing.T) {
	// Port 1 is reserved and will refuse connections.
	result := pingHealth(context.Background(), "http://127.0.0.1:1")
	if result != "unavailable" {
		t.Errorf("pingHealth = %q, want %q", result, "unavailable")
	}
}

// ---- buildStatusReport ------------------------------------------------------

func TestBuildStatusReport_AllHealthy(t *testing.T) {
	keep := healthzServer(t)
	defer keep.Close()
	guard := healthzServer(t)
	defer guard.Close()

	g := newGateForStatusTests(keep.URL, guard.URL, "")
	msg, isErr := g.buildStatusReport(context.Background())

	if isErr {
		t.Error("isErr should be false when Gate is healthy")
	}
	if !strings.Contains(msg, "operating normally") {
		t.Errorf("expected 'operating normally' in Gate line; got:\n%s", msg)
	}
	if !strings.Contains(msg, "Portcullis Keep:") {
		t.Errorf("expected Keep line; got:\n%s", msg)
	}
	if !strings.Contains(msg, "Portcullis Guard:") {
		t.Errorf("expected Guard line; got:\n%s", msg)
	}
	if strings.Count(msg, "available") != 2 {
		t.Errorf("expected Keep and Guard both 'available'; got:\n%s", msg)
	}
}

func TestBuildStatusReport_GateDegraded(t *testing.T) {
	keep := healthzServer(t)
	defer keep.Close()

	g := newGateForStatusTests(keep.URL, "", "Keep unreachable at startup")
	msg, isErr := g.buildStatusReport(context.Background())

	if !isErr {
		t.Error("isErr should be true when Gate is degraded")
	}
	if !strings.Contains(msg, "degraded") {
		t.Errorf("expected 'degraded' in Gate line; got:\n%s", msg)
	}
	if !strings.Contains(msg, "Keep unreachable at startup") {
		t.Errorf("expected degraded reason in message; got:\n%s", msg)
	}
}

func TestBuildStatusReport_KeepUnavailable(t *testing.T) {
	guard := healthzServer(t)
	defer guard.Close()

	g := newGateForStatusTests("http://127.0.0.1:1", guard.URL, "")
	msg, _ := g.buildStatusReport(context.Background())

	if !strings.Contains(msg, "Portcullis Keep:  unavailable") {
		t.Errorf("expected Keep unavailable; got:\n%s", msg)
	}
}

func TestBuildStatusReport_GuardNotConfigured(t *testing.T) {
	keep := healthzServer(t)
	defer keep.Close()

	g := newGateForStatusTests(keep.URL, "", "") // no Guard endpoint
	msg, isErr := g.buildStatusReport(context.Background())

	if isErr {
		t.Error("isErr should be false — no Guard is not an error condition")
	}
	if !strings.Contains(msg, "Portcullis Guard: not configured") {
		t.Errorf("expected 'not configured' for Guard; got:\n%s", msg)
	}
}

func TestBuildStatusReport_GuardUnavailable(t *testing.T) {
	keep := healthzServer(t)
	defer keep.Close()

	g := newGateForStatusTests(keep.URL, "http://127.0.0.1:1", "")
	msg, _ := g.buildStatusReport(context.Background())

	if !strings.Contains(msg, "Portcullis Guard: unavailable") {
		t.Errorf("expected Guard unavailable; got:\n%s", msg)
	}
}
