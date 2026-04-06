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

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/paclabsnet/PortcullisMCP/internal/shared"
)

// RunDiagnosticMode starts a minimal MCP server that registers a single
// portcullis_status pseudo-tool. Every call to that tool returns the provided
// startup error message so the connected agent receives a human-readable
// explanation of why Gate could not initialize normally.
//
// This allows Gate to remain connected to the MCP client (Claude, Copilot, etc.)
// rather than crashing, which would surface as an unresponsive tool server with
// no actionable feedback. It is only appropriate for single-tenant mode where
// a human agent is on the other end of the stdio connection.
func RunDiagnosticMode(ctx context.Context, reason string) error {
	slog.Error("gate entered diagnostic mode", "reason", reason)

	srv := mcp.NewServer(&mcp.Implementation{
		Name:    shared.ServiceGate,
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
					Text: "Portcullis Gate is in diagnostic mode: " + reason,
				}},
			}, nil, nil
		},
	)

	return srv.Run(ctx, &mcp.StdioTransport{})
}
