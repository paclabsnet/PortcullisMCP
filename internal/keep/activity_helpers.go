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
	"time"

	"github.com/paclabsnet/PortcullisMCP/internal/keep/activitylog"
	"github.com/paclabsnet/PortcullisMCP/internal/shared"
)

// activityMeta holds the request-identity fields that are identical across
// every RequestEntry and ResponseEntry emitted for a single /call or /authorize
// request. Capturing them once prevents the seven-field block from drifting
// independently across the dozen log sites in handleCall and handleAuthorize.
type activityMeta struct {
	sessionID  string
	traceID    string
	remoteAddr string
	userID     string
	agent      shared.AgentInfo
	serverName string
	toolName   string
}

// newActivityMeta builds an activityMeta from an AuthorizedRequest.
// agent comes from the original EnrichedMCPRequest because AuthorizedRequest
// does not carry it.
func newActivityMeta(req AuthorizedRequest, agent shared.AgentInfo, traceID, remoteAddr string) activityMeta {
	return activityMeta{
		sessionID:  req.SessionID,
		traceID:    traceID,
		remoteAddr: remoteAddr,
		userID:     req.Principal.UserID,
		agent:      agent,
		serverName: req.ServerName,
		toolName:   req.ToolName,
	}
}

// logRequest emits an mcp_request log entry. It is a no-op when the activity
// logger is not configured. jtis may be nil when no escalation tokens are present.
func (s *Server) logRequest(m activityMeta, args map[string]any, decision, reason string, jtis []string) {
	if s.activityLog == nil {
		return
	}
	s.activityLog.LogRequest(activitylog.RequestEntry{
		SessionID:      m.sessionID,
		TraceID:        m.traceID,
		RemoteAddr:     m.remoteAddr,
		UserID:         m.userID,
		Agent:          m.agent,
		ServerName:     m.serverName,
		ToolName:       m.toolName,
		Arguments:      args,
		PDPDecision:    decision,
		PDPReason:      reason,
		EscalationJTIs: jtis,
	})
}

// logResponse emits an mcp_response log entry. It is a no-op when the activity
// logger is not configured. escalationJTI and wfRef are empty for non-pending
// outcomes; result is non-nil only for successful tool executions.
func (s *Server) logResponse(m activityMeta, start time.Time, status, errMsg, escalationJTI, wfRef string, result any) {
	if s.activityLog == nil {
		return
	}
	s.activityLog.LogResponse(activitylog.ResponseEntry{
		SessionID:         m.sessionID,
		TraceID:           m.traceID,
		RemoteAddr:        m.remoteAddr,
		UserID:            m.userID,
		Agent:             m.agent,
		ServerName:        m.serverName,
		ToolName:          m.toolName,
		DurationMS:        time.Since(start).Milliseconds(),
		Status:            status,
		Error:             errMsg,
		EscalationJTI:     escalationJTI,
		WorkflowReference: wfRef,
		Result:            result,
	})
}
