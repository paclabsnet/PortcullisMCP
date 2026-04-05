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
	"net/http"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// MCPHTTPHandler wraps the SDK's StreamableHTTPHandler with Portcullis
// middleware (session management, identity injection, auth). Health check
// endpoints bypass all middleware.
type MCPHTTPHandler struct {
	sdkHandler http.Handler
}

// NewMCPHTTPHandler creates an MCPHTTPHandler backed by the given mcp.Server
// and optional StreamableHTTPOptions (e.g. for EventStore wiring).
func NewMCPHTTPHandler(srv *mcp.Server, opts *mcp.StreamableHTTPOptions) *MCPHTTPHandler {
	sdkHandler := mcp.NewStreamableHTTPHandler(func(_ *http.Request) *mcp.Server {
		return srv
	}, opts)
	return &MCPHTTPHandler{sdkHandler: sdkHandler}
}

// ServeHTTP implements http.Handler.
// /healthz and /readyz respond immediately with 200 OK, bypassing auth and
// session middleware. All other paths are delegated to the SDK handler
// (full middleware chain added in Task 3.3).
func (h *MCPHTTPHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/healthz", "/readyz":
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
		return
	}
	h.sdkHandler.ServeHTTP(w, r)
}
