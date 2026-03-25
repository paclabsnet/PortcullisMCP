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
	"log/slog"
	"net/http"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// pingHealth performs a GET to <endpoint>/health with a 3-second timeout.
// Returns "available" if any HTTP response is received, "unavailable" otherwise.
func pingHealth(ctx context.Context, endpoint string) string {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint+"/health", nil)
	if err != nil {
		return "unavailable"
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "unavailable"
	}
	resp.Body.Close()
	return "available"
}

// RunDegraded starts a minimal MCP server that registers a single
// portcullis_status pseudo-tool. Every call to that tool returns the provided
// startup error message so the connected agent receives a human-readable
// explanation of why Gate could not initialize normally.
//
// This allows Gate to remain connected to the MCP client (Claude, Copilot, etc.)
// rather than crashing, which would surface as an unresponsive tool server with
// no actionable feedback.
func RunDegraded(ctx context.Context, reason string) error {
	slog.Warn("gate starting in degraded mode", "reason", reason)

	srv := mcp.NewServer(&mcp.Implementation{
		Name:    "portcullis-gate",
		Version: "0.1.0",
	}, nil)

	mcp.AddTool(srv,
		&mcp.Tool{
			Name:        "portcullis_status",
			Description: "Returns the current status of Portcullis Gate. Portcullis Gate has failed to start — call this tool to see the error.",
		},
		func(_ context.Context, _ *mcp.CallToolRequest, _ any) (*mcp.CallToolResult, any, error) {
			return &mcp.CallToolResult{
				IsError: true,
				Content: []mcp.Content{&mcp.TextContent{
					Text: "Portcullis Gate is degraded: " + reason,
				}},
			}, nil, nil
		},
	)

	return srv.Run(ctx, &mcp.StdioTransport{})
}
