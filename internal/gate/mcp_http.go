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
	"crypto/sha256"
	"net/http"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/paclabsnet/PortcullisMCP/internal/shared"
)

// MCPHTTPHandler wraps the SDK's StreamableHTTPHandler with Portcullis
// middleware: health checks, authentication, and context injection.
type MCPHTTPHandler struct {
	provider   TenancyProvider
	authType   string // from endpoint.Auth.Type ("none", "bearer", "mtls")
	sdkHandler http.Handler
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
	provider TenancyProvider,
) *MCPHTTPHandler {
	sdkHandler := mcp.NewStreamableHTTPHandler(func(_ *http.Request) *mcp.Server {
		return srv
	}, sdkOpts)

	mcpEp := cfg.Server.Endpoints[MCPEndpoint]

	return &MCPHTTPHandler{
		provider:   provider,
		authType:   mcpEp.Auth.Type,
		sdkHandler: sdkHandler,
	}
}

// ServeHTTP implements http.Handler.
//
// /healthz and /readyz are served immediately with 200 OK, bypassing all
// middleware (suitable for load-balancer health probes).
//
// All other paths pass through the TenancyProvider's Authenticate method,
// which handles token extraction, session validation, and session allocation
// according to the tenancy mode. On success the session ID and raw token are
// injected into the request context before delegating to the SDK handler.
func (h *MCPHTTPHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Health checks bypass all middleware.
	switch r.URL.Path {

	// there's no 'spin-up' time for Gate, so no special case for
	// a delayed /readyz response
	case "/healthz", "/readyz":
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
		return
	}

	rawToken, sessionID, err := h.provider.Authenticate(r)
	if err != nil {
		if strings.Contains(err.Error(), "forbidden") {
			http.Error(w, "Forbidden", http.StatusForbidden)
		} else {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		}
		return
	}

	if h.authType != "" && h.authType != "none" && rawToken == "" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	ctx := r.Context()
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

	h.sdkHandler.ServeHTTP(w, r)
}
