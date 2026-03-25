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

// mock-workflow-server simulates an enterprise workflow approval system for
// testing the System Authority escalation path end-to-end without real
// infrastructure (ServiceNow, Jira, etc.).
//
// Keep sends a POST /webhook with the escalation payload. The server responds
// 200 OK immediately, then — after a configurable delay — deposits the
// pending_jwt into Guard's /token/deposit endpoint, which Gate picks up on
// its next poll cycle.
//
// Configuration (environment variables):
//
//	GUARD_URL       URL of portcullis-guard (required), e.g. http://localhost:8444
//	GUARD_TOKEN     Bearer token for Guard's API (optional)
//	APPROVAL_DELAY  How long to wait before "approving" (default: 5s)
//	                Accepts Go duration strings ("10s", "2m") or plain seconds ("10")
//	PORT            Port to listen on (default: 8090)
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"time"
)

func main() {
	guardURL := requireEnv("GUARD_URL")
	guardToken := os.Getenv("GUARD_TOKEN")
	delay := envDuration("APPROVAL_DELAY", 5*time.Second)
	port := envString("PORT", "8090")

	slog.Info("mock-workflow-server starting",
		"port", port,
		"guard_url", guardURL,
		"approval_delay", delay,
		"guard_token_set", guardToken != "",
	)

	mux := http.NewServeMux()
	mux.HandleFunc("POST /webhook", func(w http.ResponseWriter, r *http.Request) {
		handleWebhook(w, r, guardURL, guardToken, delay)
	})

	if err := http.ListenAndServe(":"+port, mux); err != nil {
		slog.Error("server exited", "error", err)
		os.Exit(1)
	}
}

// webhookPayload mirrors the payload that portcullis-keep sends to webhook
// workflow handlers (see internal/keep/workflow_webhook.go).
type webhookPayload struct {
	TraceID    string         `json:"trace_id"`
	SessionID  string         `json:"session_id"`
	Server     string         `json:"server"`
	Tool       string         `json:"tool"`
	PendingJWT string         `json:"pending_jwt"`
	User       webhookUser    `json:"user"`
}

type webhookUser struct {
	ID      string `json:"id"`
	Display string `json:"display"`
}

func handleWebhook(w http.ResponseWriter, r *http.Request, guardURL, guardToken string, delay time.Duration) {
	var payload webhookPayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
		return
	}
	if payload.PendingJWT == "" {
		http.Error(w, "bad request: missing pending_jwt", http.StatusBadRequest)
		return
	}
	if payload.User.ID == "" {
		http.Error(w, "bad request: missing user.id", http.StatusBadRequest)
		return
	}

	slog.Info("escalation request received — will approve after delay",
		"trace_id", payload.TraceID,
		"user_id", payload.User.ID,
		"server", payload.Server,
		"tool", payload.Tool,
		"approval_delay", delay,
	)

	// Respond 200 OK immediately so Keep's HTTP connection is released.
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"request_id": "mock-" + payload.TraceID,
		"status":     "accepted",
	})

	// Simulate enterprise approval asynchronously.
	go func() {
		time.Sleep(delay)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := deposit(ctx, guardURL, guardToken, payload.PendingJWT, payload.User.ID); err != nil {
			slog.Error("deposit to Guard failed",
				"trace_id", payload.TraceID,
				"user_id", payload.User.ID,
				"error", err,
			)
			return
		}
		slog.Info("escalation approved and deposited to Guard",
			"trace_id", payload.TraceID,
			"user_id", payload.User.ID,
		)
	}()
}

// deposit POSTs the pending_jwt to Guard's /token/deposit endpoint.
func deposit(ctx context.Context, guardURL, guardToken, pendingJWT, userID string) error {
	body, err := json.Marshal(map[string]string{
		"pending_jwt": pendingJWT,
		"user_id":     userID,
	})
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, guardURL+"/token/deposit", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if guardToken != "" {
		req.Header.Set("Authorization", "Bearer "+guardToken)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("post: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("guard returned HTTP %d", resp.StatusCode)
	}
	return nil
}

func requireEnv(key string) string {
	v := os.Getenv(key)
	if v == "" {
		slog.Error("required environment variable not set", "var", key)
		os.Exit(1)
	}
	return v
}

func envString(key, defaultVal string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultVal
}

// envDuration parses a duration from an environment variable.
// Accepts Go duration strings ("10s", "2m") or plain integers (treated as seconds).
func envDuration(key string, defaultVal time.Duration) time.Duration {
	v := os.Getenv(key)
	if v == "" {
		return defaultVal
	}
	if secs, err := strconv.Atoi(v); err == nil {
		return time.Duration(secs) * time.Second
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		slog.Warn("invalid duration, using default", "var", key, "value", v, "default", defaultVal)
		return defaultVal
	}
	return d
}
