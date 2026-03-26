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
	"context"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"

	"github.com/paclabsnet/PortcullisMCP/internal/shared"
	"github.com/paclabsnet/PortcullisMCP/internal/telemetry"
)

// MCPRouter defines the interface for routing MCP tool calls to backends.
type MCPRouter interface {
	CallTool(ctx context.Context, serverName, toolName string, args map[string]any) (*mcp.CallToolResult, error)
	ListAllTools(ctx context.Context) ([]shared.AnnotatedTool, error)
	Reload(ctx context.Context, backends map[string]BackendConfig) error
}

// Server is the portcullis-keep HTTP server.
// It receives enriched MCP requests from portcullis-gate instances, calls the
// PDP, and either routes the call to a backend MCP server, returns a deny, or
// submits an escalation to the enterprise workflow system.
type Server struct {
	cfg         Config
	configPath  string
	pdp         PolicyDecisionPoint
	router      MCPRouter
	workflow    WorkflowHandler
	signer      *EscalationSigner
	decisionLog *DecisionLogger
	normalizer  IdentityNormalizer
}

// NewServer creates a Keep server. configPath is retained so the admin reload
// handler can re-read the file on demand.
// cfg must already have secrets resolved (use LoadConfig, which calls the
// shared config loader, for file-based startup).
func NewServer(ctx context.Context, cfg Config, configPath string) (*Server, error) {
	cfg.Limits.ApplyDefaults()

	var pdp PolicyDecisionPoint
	switch cfg.PDP.Type {
	case "noop":
		pdp = NewNoopPDPClient()
	case "opa", "":
		pdp = NewOPAClient(cfg.PDP.Endpoint)
	default:
		return nil, fmt.Errorf("unknown pdp type %q; supported types: opa, noop", cfg.PDP.Type)
	}

	router := NewRouter(cfg.Backends)

	wf, err := NewWorkflowHandler(cfg.Escalation.Workflow)
	if err != nil {
		return nil, fmt.Errorf("create workflow handler: %w", err)
	}

	signer, err := NewEscalationSigner(cfg.EscalationRequestSigning)
	if err != nil {
		return nil, fmt.Errorf("create escalation signer: %w", err)
	}

	normalizer, err := buildIdentityNormalizer(cfg.Identity)
	if err != nil {
		return nil, fmt.Errorf("build identity normalizer: %w", err)
	}

	return &Server{
		cfg:         cfg,
		configPath:  configPath,
		pdp:         pdp,
		router:      router,
		workflow:    wf,
		signer:      signer,
		decisionLog: NewDecisionLogger(cfg.DecisionLog),
		normalizer:  normalizer,
	}, nil
}

// Run starts the HTTPS server and blocks until ctx is cancelled.
func (s *Server) Run(ctx context.Context) error {
	// Populate the tool cache before accepting requests.
	if err := s.router.Reload(ctx, s.cfg.Backends); err != nil {
		slog.Warn("initial tool cache population failed", "error", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.handleHealthz)
	mux.HandleFunc("GET /readyz", s.handleReadyz)
	mux.HandleFunc("POST /call", s.handleCall)
	mux.HandleFunc("POST /authorize", s.handleAuthorize)
	mux.HandleFunc("POST /tools", s.handleListTools)
	mux.HandleFunc("POST /log", s.handleLog)
	mux.HandleFunc("POST /admin/reload", s.adminAuthMiddleware(s.handleReload))

	// Wrap with authentication middleware if bearer token is configured.
	// Health endpoints are excluded so orchestrators can probe without credentials.
	var handler http.Handler = mux
	if s.cfg.Listen.Auth.BearerToken != "" {
		handler = s.authMiddleware(mux)
	}

	srv := &http.Server{
		Addr:    s.cfg.Listen.Address,
		Handler: handler,
	}

	go func() {
		<-ctx.Done()
		_ = s.decisionLog.Shutdown()
		_ = srv.Shutdown(context.Background())
	}()

	// Check if TLS is configured
	useTLS := s.cfg.Listen.TLS.Cert != "" && s.cfg.Listen.TLS.Key != ""

	if useTLS {
		tlsCfg, err := buildServerTLS(s.cfg.Listen.TLS)
		if err != nil {
			return fmt.Errorf("build tls config: %w", err)
		}
		srv.TLSConfig = tlsCfg
		slog.Info("portcullis-keep listening (HTTPS)", "addr", s.cfg.Listen.Address)
		return srv.ListenAndServeTLS("", "")
	} else {
		slog.Warn("portcullis-keep listening (HTTP - no TLS)", "addr", s.cfg.Listen.Address)
		return srv.ListenAndServe()
	}
}

// handleCall processes an enriched MCP tool call request from gate.
func (s *Server) handleCall(w http.ResponseWriter, r *http.Request) {
	if s.cfg.Limits.MaxRequestBodyBytes > 0 {
		r.Body = http.MaxBytesReader(w, r.Body, int64(s.cfg.Limits.MaxRequestBodyBytes))
	}

	// Extract trace context propagated by Gate and create a child span.
	ctx := otel.GetTextMapPropagator().Extract(r.Context(), propagation.HeaderCarrier(r.Header))
	ctx, span := otel.Tracer("portcullis-keep").Start(ctx, "keep.evaluate")
	defer span.End()

	var rawReq shared.EnrichedMCPRequest
	if err := json.NewDecoder(r.Body).Decode(&rawReq); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if err := shared.CheckFields(enrichedRequestChecks(rawReq, s.cfg.Limits)); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	traceID := telemetry.TraceIDFromContext(ctx)
	span.SetAttributes(
		attribute.String("tool.name", rawReq.ToolName),
		attribute.String("server.name", rawReq.ServerName),
		attribute.String("trace.id", rawReq.TraceID),
	)

	principal, normErr := s.normalizer.Normalize(ctx, rawReq.UserIdentity)
	if normErr != nil {
		span.SetStatus(codes.Error, normErr.Error())
		slog.ErrorContext(ctx, "identity normalization failed", "error", normErr, "trace_id", traceID)
		writeError(w, http.StatusServiceUnavailable, "identity normalization failed")
		return
	}
	span.SetAttributes(attribute.String("user.id", principal.UserID))

	// Construct the trusted AuthorizedRequest from verified facts.
	req := NewAuthorizedRequest(rawReq, principal)

	pdpResp, err := s.pdp.Evaluate(ctx, req)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		slog.ErrorContext(ctx, "pdp evaluate failed", "error", err, "trace_id", traceID)
		writeError(w, http.StatusServiceUnavailable, shared.ErrPDPUnavailable.Error())
		return
	}

	span.SetAttributes(attribute.String("pdp.decision", pdpResp.Decision))
	slog.InfoContext(ctx, "pdp decision",
		"decision", pdpResp.Decision,
		"tool", req.ToolName,
		"user", req.Principal.UserID,
		"trace_id", traceID,
	)

	// Log the decision
	s.decisionLog.Log(&DecisionLogEntry{
		SessionID:  req.SessionID,
		TraceID:    req.TraceID,
		UserID:     req.Principal.UserID,
		ServerName: req.ServerName,
		ToolName:   req.ToolName,
		Decision:   pdpResp.Decision,
		Reason:     pdpResp.Reason,
		Source:     "pdp",
		Arguments:  req.Arguments,
	})

	switch pdpResp.Decision {
	case "allow":
		result, err := s.router.CallTool(ctx, req.ServerName, req.ToolName, req.Arguments)
		if err != nil {
			span.SetStatus(codes.Error, err.Error())
			slog.ErrorContext(ctx, "backend call failed", "error", err, "server", req.ServerName, "tool", req.ToolName, "trace_id", traceID)
			writeError(w, http.StatusInternalServerError, "backend tool call failed")
			return
		}
		writeJSON(w, http.StatusOK, result)

	case "deny":
		span.SetStatus(codes.Error, "denied by policy")
		writeDeny(w, pdpResp.Reason, traceID)

	case "escalate":
		pendingJWT := ""
		escalationJTI := ""
		if s.signer != nil {
			jwtStr, jti, err := s.signer.Sign(req, pdpResp.Reason, pdpResp.EscalationScope)
			if err != nil {
				slog.ErrorContext(ctx, "escalation jwt sign failed", "error", err, "trace_id", traceID)
				// Non-fatal: continue without JWT; some workflow handlers may still function.
			} else {
				pendingJWT = jwtStr
				escalationJTI = jti
			}
		} else {
			slog.WarnContext(ctx, "escalation signer not configured; escalation_jti will be empty and Gate cannot auto-claim the token",
				"tool", req.ToolName, "user", req.Principal.UserID, "trace_id", traceID)
		}
		wfRef, err := s.workflow.Submit(ctx, req, pendingJWT)
		if err != nil {
			span.SetStatus(codes.Error, err.Error())
			slog.ErrorContext(ctx, "workflow submit failed", "error", err, "trace_id", traceID)
			writeError(w, http.StatusInternalServerError, "failed to submit escalation")
			return
		}
		// If neither the signed JWT nor a workflow reference was produced, the
		// escalation cannot be actioned by Gate or the user. Failing here is
		// better than returning a 202 that looks successful but leads nowhere.
		if pendingJWT == "" && wfRef == "" {
			span.SetStatus(codes.Error, "escalation misconfigured")
			slog.ErrorContext(ctx, "escalation required but no approval mechanism available — configure escalation_request_signing.key",
				"tool", req.ToolName, "user", req.Principal.UserID, "trace_id", traceID)
			writeError(w, http.StatusInternalServerError, "escalation required but no approval mechanism is available — check server configuration")
			return
		}
		slog.InfoContext(ctx, "escalation pending",
			"tool", req.ToolName,
			"server", req.ServerName,
			"user", req.Principal.UserID,
			"escalation_jti", escalationJTI,
			"workflow_reference", wfRef,
			"trace_id", traceID,
		)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"status":             "escalation_pending",
			"reason":             pdpResp.Reason,
			"workflow_reference": wfRef,
			"escalation_jti":     escalationJTI,
			"pending_jwt":        pendingJWT,
		})

	case "workflow":
		if !s.hasWorkflow() {
			span.SetStatus(codes.Error, "workflow required but not configured")
			slog.ErrorContext(ctx, "workflow decision but no workflow handler is configured",
				"tool", req.ToolName, "user", req.Principal.UserID, "trace_id", traceID)
			writeDeny(w, "this action requires external workflow approval but no workflow system is configured — contact your administrator", traceID)
			return
		}
		pendingJWT := ""
		escalationJTI := ""
		if s.signer != nil {
			jwtStr, jti, err := s.signer.Sign(req, pdpResp.Reason, pdpResp.EscalationScope)
			if err != nil {
				slog.ErrorContext(ctx, "workflow jwt sign failed", "error", err, "trace_id", traceID)
			} else {
				pendingJWT = jwtStr
				escalationJTI = jti
			}
		} else {
			slog.WarnContext(ctx, "escalation signer not configured; workflow approval cannot be deposited to Guard",
				"tool", req.ToolName, "user", req.Principal.UserID, "trace_id", traceID)
		}
		wfRef, err := s.workflow.Submit(ctx, req, pendingJWT)
		if err != nil {
			span.SetStatus(codes.Error, err.Error())
			slog.ErrorContext(ctx, "workflow submit failed", "error", err, "trace_id", traceID)
			writeError(w, http.StatusInternalServerError, "failed to submit workflow request")
			return
		}
		// If neither the signed JWT nor a workflow reference was produced, the
		// approval cannot be actioned. Failing here is better than returning a
		// 202 that looks successful but leads nowhere.
		if pendingJWT == "" && wfRef == "" {
			span.SetStatus(codes.Error, "workflow misconfigured")
			slog.ErrorContext(ctx, "workflow required but no approval mechanism available — configure escalation_request_signing.key",
				"tool", req.ToolName, "user", req.Principal.UserID, "trace_id", traceID)
			writeError(w, http.StatusInternalServerError, "workflow required but no approval mechanism is available — check server configuration")
			return
		}
		slog.InfoContext(ctx, "workflow pending",
			"tool", req.ToolName,
			"server", req.ServerName,
			"user", req.Principal.UserID,
			"escalation_jti", escalationJTI,
			"workflow_reference", wfRef,
			"trace_id", traceID,
		)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"status":             "workflow_pending",
			"reason":             pdpResp.Reason,
			"workflow_reference": wfRef,
			"escalation_jti":     escalationJTI,
			"pending_jwt":        pendingJWT,
		})

	default:
		span.SetStatus(codes.Error, "unknown decision")
		slog.ErrorContext(ctx, "unknown pdp decision", "decision", pdpResp.Decision, "trace_id", traceID)
		writeDeny(w, "unknown pdp decision — denied by default", traceID)
	}
}

// handleAuthorize evaluates the PDP for a gate-local tool call and returns the
// decision without executing the tool. Gate uses this for local filesystem ops:
// it asks Keep "is this allowed?" and, if so, executes the tool locally itself.
func (s *Server) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	if s.cfg.Limits.MaxRequestBodyBytes > 0 {
		r.Body = http.MaxBytesReader(w, r.Body, int64(s.cfg.Limits.MaxRequestBodyBytes))
	}

	ctx := otel.GetTextMapPropagator().Extract(r.Context(), propagation.HeaderCarrier(r.Header))
	ctx, span := otel.Tracer("portcullis-keep").Start(ctx, "keep.authorize")
	defer span.End()

	var rawReq shared.EnrichedMCPRequest
	if err := json.NewDecoder(r.Body).Decode(&rawReq); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if err := shared.CheckFields(enrichedRequestChecks(rawReq, s.cfg.Limits)); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	traceID := telemetry.TraceIDFromContext(ctx)
	span.SetAttributes(
		attribute.String("tool.name", rawReq.ToolName),
		attribute.String("server.name", rawReq.ServerName),
		attribute.String("trace.id", rawReq.TraceID),
	)

	principal, normErr := s.normalizer.Normalize(ctx, rawReq.UserIdentity)
	if normErr != nil {
		span.SetStatus(codes.Error, normErr.Error())
		slog.ErrorContext(ctx, "identity normalization failed", "error", normErr, "trace_id", traceID)
		writeError(w, http.StatusServiceUnavailable, "identity normalization failed")
		return
	}
	span.SetAttributes(attribute.String("user.id", principal.UserID))

	// Construct the trusted AuthorizedRequest from verified facts.
	req := NewAuthorizedRequest(rawReq, principal)

	pdpResp, err := s.pdp.Evaluate(ctx, req)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		slog.ErrorContext(ctx, "pdp evaluate failed", "error", err, "trace_id", traceID)
		writeError(w, http.StatusServiceUnavailable, shared.ErrPDPUnavailable.Error())
		return
	}

	span.SetAttributes(attribute.String("pdp.decision", pdpResp.Decision))
	slog.InfoContext(ctx, "pdp decision (authorize)",
		"decision", pdpResp.Decision,
		"tool", req.ToolName,
		"user", req.Principal.UserID,
		"trace_id", traceID,
	)

	s.decisionLog.Log(&DecisionLogEntry{
		SessionID:  req.SessionID,
		TraceID:    req.TraceID,
		UserID:     req.Principal.UserID,
		ServerName: req.ServerName,
		ToolName:   req.ToolName,
		Decision:   pdpResp.Decision,
		Reason:     pdpResp.Reason,
		Source:     "pdp",
		Arguments:  req.Arguments,
	})

	switch pdpResp.Decision {
	case "allow":
		writeJSON(w, http.StatusOK, pdpResp)

	case "deny":
		span.SetStatus(codes.Error, "denied by policy")
		writeDeny(w, pdpResp.Reason, traceID)

	case "escalate":
		pendingJWT := ""
		escalationJTI := ""
		if s.signer != nil {
			jwtStr, jti, err := s.signer.Sign(req, pdpResp.Reason, pdpResp.EscalationScope)
			if err != nil {
				slog.ErrorContext(ctx, "escalation jwt sign failed", "error", err, "trace_id", traceID)
			} else {
				pendingJWT = jwtStr
				escalationJTI = jti
			}
		} else {
			slog.WarnContext(ctx, "escalation signer not configured; escalation_jti will be empty and Gate cannot auto-claim the token",
				"tool", req.ToolName, "user", req.Principal.UserID, "trace_id", traceID)
		}
		wfRef, err := s.workflow.Submit(ctx, req, pendingJWT)
		if err != nil {
			span.SetStatus(codes.Error, err.Error())
			slog.ErrorContext(ctx, "workflow submit failed", "error", err, "trace_id", traceID)
			writeError(w, http.StatusInternalServerError, "failed to submit escalation")
			return
		}
		// If neither the signed JWT nor a workflow reference was produced, the
		// escalation cannot be actioned by Gate or the user. Failing here is
		// better than returning a 202 that looks successful but leads nowhere.
		if pendingJWT == "" && wfRef == "" {
			span.SetStatus(codes.Error, "escalation misconfigured")
			slog.ErrorContext(ctx, "escalation required but no approval mechanism available — configure escalation_request_signing.key",
				"tool", req.ToolName, "user", req.Principal.UserID, "trace_id", traceID)
			writeError(w, http.StatusInternalServerError, "escalation required but no approval mechanism is available — check server configuration")
			return
		}
		slog.InfoContext(ctx, "escalation pending",
			"tool", req.ToolName,
			"server", req.ServerName,
			"user", req.Principal.UserID,
			"escalation_jti", escalationJTI,
			"workflow_reference", wfRef,
			"trace_id", traceID,
		)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"status":             "escalation_pending",
			"reason":             pdpResp.Reason,
			"workflow_reference": wfRef,
			"escalation_jti":     escalationJTI,
			"pending_jwt":        pendingJWT,
		})

	case "workflow":
		if !s.hasWorkflow() {
			span.SetStatus(codes.Error, "workflow required but not configured")
			slog.ErrorContext(ctx, "workflow decision but no workflow handler is configured",
				"tool", req.ToolName, "user", req.Principal.UserID, "trace_id", traceID)
			writeDeny(w, "this action requires external workflow approval but no workflow system is configured — contact your administrator", traceID)
			return
		}
		pendingJWT := ""
		escalationJTI := ""
		if s.signer != nil {
			jwtStr, jti, err := s.signer.Sign(req, pdpResp.Reason, pdpResp.EscalationScope)
			if err != nil {
				slog.ErrorContext(ctx, "workflow jwt sign failed", "error", err, "trace_id", traceID)
			} else {
				pendingJWT = jwtStr
				escalationJTI = jti
			}
		} else {
			slog.WarnContext(ctx, "escalation signer not configured; workflow approval cannot be deposited to Guard",
				"tool", req.ToolName, "user", req.Principal.UserID, "trace_id", traceID)
		}
		wfRef, err := s.workflow.Submit(ctx, req, pendingJWT)
		if err != nil {
			span.SetStatus(codes.Error, err.Error())
			slog.ErrorContext(ctx, "workflow submit failed", "error", err, "trace_id", traceID)
			writeError(w, http.StatusInternalServerError, "failed to submit workflow request")
			return
		}
		// If neither the signed JWT nor a workflow reference was produced, the
		// approval cannot be actioned. Failing here is better than returning a
		// 202 that looks successful but leads nowhere.
		if pendingJWT == "" && wfRef == "" {
			span.SetStatus(codes.Error, "workflow misconfigured")
			slog.ErrorContext(ctx, "workflow required but no approval mechanism available — configure escalation_request_signing.key",
				"tool", req.ToolName, "user", req.Principal.UserID, "trace_id", traceID)
			writeError(w, http.StatusInternalServerError, "workflow required but no approval mechanism is available — check server configuration")
			return
		}
		slog.InfoContext(ctx, "workflow pending",
			"tool", req.ToolName,
			"server", req.ServerName,
			"user", req.Principal.UserID,
			"escalation_jti", escalationJTI,
			"workflow_reference", wfRef,
			"trace_id", traceID,
		)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"status":             "workflow_pending",
			"reason":             pdpResp.Reason,
			"workflow_reference": wfRef,
			"escalation_jti":     escalationJTI,
			"pending_jwt":        pendingJWT,
		})

	default:
		span.SetStatus(codes.Error, "unknown decision")
		slog.ErrorContext(ctx, "unknown pdp decision", "decision", pdpResp.Decision, "trace_id", traceID)
		writeDeny(w, "unknown pdp decision — denied by default", traceID)
	}
}

// handleListTools returns the aggregated tool list from all backends.
func (s *Server) handleListTools(w http.ResponseWriter, r *http.Request) {
	tools, err := s.router.ListAllTools(r.Context())
	if err != nil {
		slog.Error("list tools failed", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to list tools")
		return
	}
	writeJSON(w, http.StatusOK, tools)
}

// handleLog receives decision log entries from portcullis-gate instances
// for fast-path decisions and queues them for batched forwarding.
func (s *Server) handleLog(w http.ResponseWriter, r *http.Request) {
	if s.cfg.Limits.MaxRequestBodyBytes > 0 {
		r.Body = http.MaxBytesReader(w, r.Body, int64(s.cfg.Limits.MaxRequestBodyBytes))
	}

	var entries []DecisionLogEntry
	if err := json.NewDecoder(r.Body).Decode(&entries); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if s.cfg.Limits.MaxLogBatchSize > 0 && len(entries) > s.cfg.Limits.MaxLogBatchSize {
		writeError(w, http.StatusBadRequest,
			fmt.Sprintf("log batch exceeds maximum of %d entries", s.cfg.Limits.MaxLogBatchSize))
		return
	}

	// Validate each entry; reject individual records that are invalid and process the rest.
	validDecisions := map[string]bool{
		"allow": true, "deny": true, "escalate": true, "workflow": true, "": true,
	}
	filtered := entries[:0]
	for _, e := range entries {
		invalid := false
		for _, chk := range []shared.FieldCheck{
			{e.UserID, "user_id", s.cfg.Limits.MaxUserIDBytes},
			{e.ToolName, "tool_name", s.cfg.Limits.MaxToolNameBytes},
			{e.ServerName, "server_name", s.cfg.Limits.MaxServerNameBytes},
			{e.TraceID, "trace_id", s.cfg.Limits.MaxTraceIDBytes},
			{e.SessionID, "session_id", s.cfg.Limits.MaxSessionIDBytes},
			{e.Reason, "reason", s.cfg.Limits.MaxReasonBytes},
		} {
			if err := shared.CheckLen(chk.Value, chk.Name, chk.Max); err != nil {
				slog.Warn("dropping oversized log entry", "field", chk.Name, "tool", e.ToolName)
				invalid = true
				break
			}
		}
		if !invalid && !validDecisions[e.Decision] {
			slog.Warn("dropping log entry with unknown decision", "decision", e.Decision, "tool", e.ToolName)
			invalid = true
		}
		if !invalid {
			filtered = append(filtered, e)
		}
	}
	entries = filtered

	// Queue all valid entries to the decision logger.
	for i := range entries {
		s.decisionLog.Log(&entries[i])
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status": "accepted",
		"count":  len(entries),
	})
}

// adminAuthMiddleware guards admin endpoints with the X-Api-Key header.
func (s *Server) adminAuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.cfg.Admin.Token == "" {
			writeError(w, http.StatusForbidden, "forbidden")
			return
		}
		token := r.Header.Get("X-Api-Key")
		if subtle.ConstantTimeCompare([]byte(token), []byte(s.cfg.Admin.Token)) != 1 {
			slog.Warn("unauthorized admin request", "remote_addr", r.RemoteAddr, "path", r.URL.Path)
			writeError(w, http.StatusUnauthorized, "invalid or missing X-Api-Key")
			return
		}
		next(w, r)
	}
}

// handleReload re-reads keep.yaml from disk and refreshes the backend
// connections and tool cache. Only the backends section is reloaded; all other
// config (TLS, PDP, etc.) requires a full restart.
func (s *Server) handleReload(w http.ResponseWriter, r *http.Request) {
	cfg, err := LoadConfig(r.Context(), s.configPath)
	if err != nil {
		slog.Error("admin reload: read config failed", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to read configuration")
		return
	}
	if err := s.router.Reload(r.Context(), cfg.Backends); err != nil {
		slog.Error("admin reload: backend reload failed", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to reload backends")
		return
	}
	s.cfg.Backends = cfg.Backends
	writeJSON(w, http.StatusOK, map[string]string{"status": "reloaded"})
}

// buildServerTLS creates a tls.Config for the Keep server.
// If ClientCA is set, mTLS client verification is required.
func buildServerTLS(cfg TLSConfig) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(cfg.Cert, cfg.Key)
	if err != nil {
		return nil, fmt.Errorf("load server cert: %w", err)
	}
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
	}
	if cfg.ClientCA != "" {
		caData, err := os.ReadFile(cfg.ClientCA)
		if err != nil {
			return nil, fmt.Errorf("read client CA: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caData) {
			return nil, fmt.Errorf("parse client CA: no valid certificates found")
		}
		tlsCfg.ClientCAs = pool
		tlsCfg.ClientAuth = tls.RequireAndVerifyClientCert
	}
	return tlsCfg, nil
}

// hasWorkflow returns true when a real workflow handler is configured.
// noopWorkflow (the default when no workflow type is set) does not count —
// a "workflow" PDP decision requires an actual external system to approve it.
func (s *Server) hasWorkflow() bool {
	_, isNoop := s.workflow.(*noopWorkflow)
	return !isNoop
}

// enrichedRequestChecks returns the field-length checks for an EnrichedMCPRequest.
// Centralising them here means handleCall and handleAuthorize stay in sync automatically.
func enrichedRequestChecks(req shared.EnrichedMCPRequest, limits LimitsConfig) []shared.FieldCheck {
	return []shared.FieldCheck{
		{req.ServerName, "server_name", limits.MaxServerNameBytes},
		{req.ToolName, "tool_name", limits.MaxToolNameBytes},
		{req.TraceID, "trace_id", limits.MaxTraceIDBytes},
		{req.SessionID, "session_id", limits.MaxSessionIDBytes},
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// writeDeny writes a 403 response that includes the trace ID when available,
// so users can reference it when escalating to the security team.
func writeDeny(w http.ResponseWriter, reason, traceID string) {
	body := map[string]string{"error": reason}
	if traceID != "" {
		body["trace_id"] = traceID
	}
	writeJSON(w, http.StatusForbidden, body)
}

// handleHealthz is the liveness probe. Returns 200 as long as the HTTP server
// is running and able to handle requests.
func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// handleReadyz is the readiness probe. Returns 200 when Keep is fully
// initialized and able to serve traffic: PDP and router are loaded, and the
// tool cache has been populated (at least attempted). Signer status is
// included in the response body as an informational field.
func (s *Server) handleReadyz(w http.ResponseWriter, r *http.Request) {
	tools, err := s.router.ListAllTools(r.Context())
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"status": "unavailable",
			"reason": "tool cache unavailable: " + err.Error(),
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status":            "ready",
		"tools":             len(tools),
		"signer_configured": s.signer != nil,
	})
}

// authMiddleware validates the bearer token if configured.
// Health endpoints (/healthz, /readyz) are exempt so orchestrators can probe
// without credentials.
func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" || r.URL.Path == "/readyz" {
			next.ServeHTTP(w, r)
			return
		}

		auth := r.Header.Get("Authorization")
		expected := "Bearer " + s.cfg.Listen.Auth.BearerToken

		if subtle.ConstantTimeCompare([]byte(auth), []byte(expected)) != 1 {
			slog.Warn("unauthorized request",
				"remote_addr", r.RemoteAddr,
				"path", r.URL.Path,
				"has_auth", auth != "",
			)
			writeError(w, http.StatusUnauthorized, "invalid or missing bearer token")
			return
		}

		next.ServeHTTP(w, r)
	})
}
