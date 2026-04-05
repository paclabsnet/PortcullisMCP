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
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"net/http"

	"github.com/google/uuid"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/paclabsnet/PortcullisMCP/internal/shared"
)

// MCPHTTPHandler wraps the SDK's StreamableHTTPHandler with Portcullis
// middleware: health checks, token extraction, session ownership validation,
// and context injection.
type MCPHTTPHandler struct {
	tenancy     string         // "single" or "multi"
	authType    string         // from endpoint.Auth.Type ("none", "bearer", "mtls")
	tokenHeader string         // header name for inbound token (e.g. "X-User-Token")
	sessions    SessionStore   // session persistence
	identity    IdentitySource // global identity source (used for single-tenant fallback)
	sdkHandler  http.Handler   // downstream StreamableHTTPHandler
}

// credentialFingerprint returns a SHA-256 hash of the raw token string. This
// is stored in session state and used to detect cross-tenant session hijacking.
func credentialFingerprint(rawToken string) []byte {
	h := sha256.Sum256([]byte(rawToken))
	return h[:]
}

// NewMCPHTTPHandler creates an MCPHTTPHandler. sdkOpts (may be nil) are
// forwarded to the SDK for EventStore wiring and similar options.
func NewMCPHTTPHandler(
	srv *mcp.Server,
	sdkOpts *mcp.StreamableHTTPOptions,
	cfg Config,
	sessions SessionStore,
	identity IdentitySource,
) *MCPHTTPHandler {
	sdkHandler := mcp.NewStreamableHTTPHandler(func(_ *http.Request) *mcp.Server {
		return srv
	}, sdkOpts)

	mcpEp := cfg.Server.Endpoints[MCPEndpoint]

	return &MCPHTTPHandler{
		tenancy:     cfg.Tenancy,
		authType:    mcpEp.Auth.Type,
		tokenHeader: mcpEp.Auth.Credentials.Header,
		sessions:    sessions,
		identity:    identity,
		sdkHandler:  sdkHandler,
	}
}

// ServeHTTP implements http.Handler.
//
// /healthz and /readyz are served immediately with 200 OK, bypassing all
// middleware (suitable for load-balancer health probes).
//
// All other paths pass through session management and identity injection:
//
//  1. Extract Mcp-Session-Id header.
//  2. Extract the bearer token from the configured header.
//     In single-tenant mode, fall back to the globally cached identity token.
//  3. If auth is required and no token is available → 401 Unauthorized.
//  4. In multi-tenant mode, if a session ID was supplied, validate the
//     token's credential fingerprint against the stored fingerprint.
//     Mismatch → 403. Storage error → 500.
//  5. If the session was new or not found, generate a fresh session ID and
//     persist the credential fingerprint.
//  6. Inject session ID and raw token into the request context.
//  7. Delegate to the SDK StreamableHTTPHandler.
func (h *MCPHTTPHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Health checks bypass all middleware.
	switch r.URL.Path {
	case "/healthz", "/readyz":
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
		return
	}

	ctx := r.Context()

	// --- Step 1: Extract Mcp-Session-Id ---
	sessionID := r.Header.Get("Mcp-Session-Id")

	// --- Step 2: Extract token ---
	rawToken := ""
	if h.tokenHeader != "" {
		rawToken = r.Header.Get(h.tokenHeader)
	}
	// Single-tenant fallback: use the globally cached identity token when the
	// per-request header is absent.
	if rawToken == "" && h.tenancy != "multi" && h.identity != nil {
		rawToken = h.identity.Get(ctx).RawToken
	}

	// --- Step 3: Enforce auth requirement ---
	if h.authType != "" && h.authType != "none" && rawToken == "" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// --- Steps 4 & 5: Session ownership check / new-session generation ---
	if h.sessions != nil {
		if sessionID != "" && h.tenancy == "multi" {
			storedState, _, err := h.sessions.GetSession(ctx, sessionID)
			switch {
			case errors.Is(err, ErrSessionNotFound):
				// Session expired or unknown — generate a new one below.
				sessionID = ""
			case err != nil:
				// Storage failure: preserve the security boundary.
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				return
			default:
				// Session found: enforce credential fingerprint.
				if !bytes.Equal(storedState, credentialFingerprint(rawToken)) {
					http.Error(w, "Forbidden", http.StatusForbidden)
					return
				}
			}
		}

		// --- Step 6: Generate new session when needed ---
		if sessionID == "" && rawToken != "" {
			sessionID = uuid.NewString()
			fp := credentialFingerprint(rawToken)
			// userID is intentionally empty in multi-tenant mode: Gate does not
			// parse inbound tokens; the PDP is the authority on token identity.
			if err := h.sessions.SaveSession(ctx, sessionID, "", fp); err != nil {
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				return
			}
		}
	}

	// --- Step 7: Inject sessionID and raw token into context ---
	if sessionID != "" {
		ctx = withSessionID(ctx, sessionID)
	}
	if rawToken != "" {
		// Store the raw token as a minimal UserIdentity so downstream gate
		// logic (handleToolCall, forwarder) can forward it to the PDP without
		// re-reading the request headers.
		ctx = context.WithValue(ctx, identityKey, shared.UserIdentity{RawToken: rawToken})
	}
	r = r.WithContext(ctx)

	// --- Step 8: Delegate ---
	h.sdkHandler.ServeHTTP(w, r)
}
