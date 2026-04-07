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
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"

	"github.com/paclabsnet/PortcullisMCP/internal/shared"
	"github.com/paclabsnet/PortcullisMCP/internal/shared/tlsutil"
	"github.com/paclabsnet/PortcullisMCP/internal/telemetry"
)

type keepCtxKey string

const clientHeadersKey keepCtxKey = "clientHeaders"

// withClientHeaders returns a new context carrying the validated client headers.
func withClientHeaders(ctx context.Context, headers map[string][]string) context.Context {
	return context.WithValue(ctx, clientHeadersKey, headers)
}

// clientHeadersFromContext returns the client headers stored in ctx, or nil if absent.
func clientHeadersFromContext(ctx context.Context) map[string][]string {
	v, _ := ctx.Value(clientHeadersKey).(map[string][]string)
	return v
}

// MCPRouter defines the interface for routing MCP tool calls to backends.
type MCPRouter interface {
	CallTool(ctx context.Context, serverName, toolName string, args map[string]any) (*mcp.CallToolResult, error)
	ListAllTools(ctx context.Context) ([]shared.AnnotatedTool, error)
	Reload(ctx context.Context, backends []BackendConfig) error
}

// Server is the portcullis-keep HTTP server.
type Server struct {
	cfg         Config
	pdp         PolicyDecisionPoint
	router      MCPRouter
	workflow    WorkflowHandler
	signer      *EscalationSigner
	decisionLog *DecisionLogger
	normalizer  IdentityNormalizer
}

// NewServer creates a Keep server.
func NewServer(ctx context.Context, cfg Config) (*Server, error) {
	var pdp PolicyDecisionPoint
	switch cfg.Responsibility.Policy.Strategy {
	case "noop":
		pdp = NewNoopPDPClient()
	case "opa", "":
		pdp = NewOPAClient(cfg.Responsibility.Policy.OPA.Endpoint)
	default:
		return nil, fmt.Errorf("unknown pdp strategy %q; supported: opa, noop", cfg.Responsibility.Policy.Strategy)
	}

	router := NewRouter(cfg.Responsibility.Backends)

	wf, err := NewWorkflowHandler(cfg.Responsibility.Workflow)
	if err != nil {
		return nil, fmt.Errorf("create workflow handler: %w", err)
	}

	signer, err := NewEscalationSigner(cfg.Responsibility.Issuance)
	if err != nil {
		return nil, fmt.Errorf("create escalation signer: %w", err)
	}

	normalizer, err := buildIdentityNormalizer(&cfg.Identity)
	if err != nil {
		return nil, fmt.Errorf("build identity normalizer: %w", err)
	}
	normalizer, err = initNormalizerWebhook(ctx, normalizer, &cfg.Peers, cfg.Identity.Normalizer, cfg.Operations.Storage, cfg.Mode)
	if err != nil {
		return nil, fmt.Errorf("init normalization webhook: %w", err)
	}

	return &Server{
		cfg: cfg,
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
	if err := s.router.Reload(ctx, s.cfg.Responsibility.Backends); err != nil {
		slog.Warn("initial tool cache population failed", "error", err)
	}

	mainEndpoint, ok := s.cfg.Server.Endpoints["main"]
	if !ok {
		return fmt.Errorf("server.endpoints.main is required")
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.handleHealthz)
	mux.HandleFunc("GET /readyz", s.handleReadyz)
	mux.HandleFunc("POST /call", s.handleCall)
	mux.HandleFunc("POST /authorize", s.handleAuthorize)
	mux.HandleFunc("POST /tools", s.handleListTools)
	mux.HandleFunc("POST /log", s.handleLog)

	var handler http.Handler = mux
	if mainEndpoint.Auth.Credentials.BearerToken != "" {
		handler = s.authMiddleware(mux)
	}

	srv := &http.Server{
		Addr:    mainEndpoint.Listen,
		Handler: handler,
	}

	go func() {
		<-ctx.Done()
		if s.decisionLog != nil {
			_ = s.decisionLog.Shutdown()
		}
		_ = srv.Shutdown(context.Background())
	}()

	// Check if TLS is configured
	useTLS := mainEndpoint.TLS.Cert != "" && mainEndpoint.TLS.Key != ""

	if useTLS {
		tlsCfg, err := tlsutil.BuildServerTLS(mainEndpoint.TLS)
		if err != nil {
			return fmt.Errorf("build tls config: %w", err)
		}
		srv.TLSConfig = tlsCfg
		slog.Info("portcullis-keep listening (HTTPS)", "addr", mainEndpoint.Listen)
		return srv.ListenAndServeTLS("", "")
	} else {
		slog.Warn("portcullis-keep listening (HTTP - no TLS)", "addr", mainEndpoint.Listen)
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
	ctx, span := otel.Tracer(shared.ServiceKeep).Start(ctx, "keep.evaluate")
	defer span.End()

	var rawReq shared.EnrichedMCPRequest
	if err := json.NewDecoder(r.Body).Decode(&rawReq); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if err := checkAPIVersion(rawReq.APIVersion); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	if err := shared.CheckFields(enrichedRequestChecks(rawReq, s.cfg.Limits)); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	if err := validateClientHeaders(rawReq.ClientHeaders, s.cfg.Limits); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	if len(rawReq.ClientHeaders) > 0 {
		ctx = withClientHeaders(ctx, rawReq.ClientHeaders)
	}

	traceID := telemetry.TraceIDFromContext(ctx)
	if traceID == "" {
		traceID = rawReq.TraceID
	}
	span.SetAttributes(
		attribute.String("tool.name", rawReq.ToolName),
		attribute.String("server.name", rawReq.ServerName),
		attribute.String("trace.id", traceID),
	)

	principal, normErr := s.normalizer.Normalize(ctx, rawReq.UserIdentity)
	if normErr != nil {
		span.SetStatus(codes.Error, normErr.Error())
		slog.ErrorContext(ctx, "identity normalization failed", "error", normErr, "trace_id", traceID)

		if verifyErr := (*shared.IdentityVerificationError)(nil); errors.As(normErr, &verifyErr) {
			writeError(w, http.StatusUnauthorized, normErr.Error())
			return
		}
		if validErr := (*NormalizationValidationError)(nil); errors.As(normErr, &validErr) {
			writeError(w, http.StatusForbidden, normErr.Error())
			return
		}

		writeError(w, http.StatusServiceUnavailable, "identity normalization failed")
		return
	}
	span.SetAttributes(attribute.String("user.id", principal.UserID))

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
	if s.decisionLog != nil {
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
	}

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
			} else {
				pendingJWT = jwtStr
				escalationJTI = jti
			}
		}
		wfRef, err := s.workflow.Submit(ctx, req, pendingJWT)
		if err != nil {
			span.SetStatus(codes.Error, err.Error())
			slog.ErrorContext(ctx, "workflow submit failed", "error", err, "trace_id", traceID)
			writeError(w, http.StatusInternalServerError, "failed to submit escalation")
			return
		}
		if pendingJWT == "" && wfRef == "" {
			span.SetStatus(codes.Error, "escalation misconfigured")
			slog.ErrorContext(ctx, "escalation required but no approval mechanism available",
				"tool", req.ToolName, "user", req.Principal.UserID, "trace_id", traceID)
			writeError(w, http.StatusInternalServerError, "escalation required but no approval mechanism is available")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"status":             "escalation_pending",
			"reason":             pdpResp.Reason,
			"workflow_reference": wfRef,
			"escalation_jti":     escalationJTI,
			"pending_jwt":        pendingJWT,
			"trace_id":           traceID,
		})

	case "workflow":
		if !s.hasWorkflow() {
			span.SetStatus(codes.Error, "workflow required but not configured")
			writeDeny(w, "this action requires external workflow approval but no workflow system is configured", traceID)
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
		}
		wfRef, err := s.workflow.Submit(ctx, req, pendingJWT)
		if err != nil {
			span.SetStatus(codes.Error, err.Error())
			slog.ErrorContext(ctx, "workflow submit failed", "error", err, "trace_id", traceID)
			writeError(w, http.StatusInternalServerError, "failed to submit workflow request")
			return
		}
		if pendingJWT == "" && wfRef == "" {
			span.SetStatus(codes.Error, "workflow misconfigured")
			writeError(w, http.StatusInternalServerError, "workflow required but no approval mechanism is available")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"status":             "workflow_pending",
			"reason":             pdpResp.Reason,
			"workflow_reference": wfRef,
			"escalation_jti":     escalationJTI,
			"pending_jwt":        pendingJWT,
			"trace_id":           traceID,
		})

	default:
		span.SetStatus(codes.Error, "unknown decision")
		writeDeny(w, "unknown pdp decision — denied by default", traceID)
	}
}

// handleAuthorize evaluates the PDP for a gate-local tool call.
func (s *Server) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	if s.cfg.Limits.MaxRequestBodyBytes > 0 {
		r.Body = http.MaxBytesReader(w, r.Body, int64(s.cfg.Limits.MaxRequestBodyBytes))
	}

	ctx := otel.GetTextMapPropagator().Extract(r.Context(), propagation.HeaderCarrier(r.Header))
	ctx, span := otel.Tracer(shared.ServiceKeep).Start(ctx, "keep.authorize")
	defer span.End()

	var rawReq shared.EnrichedMCPRequest
	if err := json.NewDecoder(r.Body).Decode(&rawReq); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if err := checkAPIVersion(rawReq.APIVersion); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	if err := shared.CheckFields(enrichedRequestChecks(rawReq, s.cfg.Limits)); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	traceID := telemetry.TraceIDFromContext(ctx)
	if traceID == "" {
		traceID = rawReq.TraceID
	}

	principal, normErr := s.normalizer.Normalize(ctx, rawReq.UserIdentity)
	if normErr != nil {
		if verifyErr := (*shared.IdentityVerificationError)(nil); errors.As(normErr, &verifyErr) {
			writeError(w, http.StatusUnauthorized, normErr.Error())
			return
		}
		if validErr := (*NormalizationValidationError)(nil); errors.As(normErr, &validErr) {
			writeError(w, http.StatusForbidden, normErr.Error())
			return
		}
		writeError(w, http.StatusServiceUnavailable, "identity normalization failed")
		return
	}

	req := NewAuthorizedRequest(rawReq, principal)
	pdpResp, err := s.pdp.Evaluate(ctx, req)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, shared.ErrPDPUnavailable.Error())
		return
	}

	if s.decisionLog != nil {
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
	}

	switch pdpResp.Decision {
	case "allow":
		writeJSON(w, http.StatusOK, pdpResp)
	case "deny":
		writeDeny(w, pdpResp.Reason, traceID)
	case "escalate":
		pendingJWT := ""
		escalationJTI := ""
		if s.signer != nil {
			pendingJWT, escalationJTI, _ = s.signer.Sign(req, pdpResp.Reason, pdpResp.EscalationScope)
		}
		wfRef, _ := s.workflow.Submit(ctx, req, pendingJWT)
		writeJSON(w, http.StatusAccepted, map[string]string{
			"status":             "escalation_pending",
			"reason":             pdpResp.Reason,
			"workflow_reference": wfRef,
			"escalation_jti":     escalationJTI,
			"pending_jwt":        pendingJWT,
			"trace_id":           traceID,
		})
	default:
		writeDeny(w, "unsupported decision for authorize", traceID)
	}
}

// handleListTools returns the aggregated tool list from all backends.
func (s *Server) handleListTools(w http.ResponseWriter, r *http.Request) {
	tools, err := s.router.ListAllTools(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list tools")
		return
	}
	writeJSON(w, http.StatusOK, tools)
}

// handleLog receives decision log entries from portcullis-gate instances.
func (s *Server) handleLog(w http.ResponseWriter, r *http.Request) {
	if s.cfg.Limits.MaxRequestBodyBytes > 0 {
		r.Body = http.MaxBytesReader(w, r.Body, int64(s.cfg.Limits.MaxRequestBodyBytes))
	}

	var batch struct {
		APIVersion string             `json:"api_version"`
		Entries    []DecisionLogEntry `json:"entries"`
	}
	if err := json.NewDecoder(r.Body).Decode(&batch); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if s.cfg.Limits.MaxLogBatchSize > 0 && len(batch.Entries) > s.cfg.Limits.MaxLogBatchSize {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("batch size %d exceeds maximum of %d", len(batch.Entries), s.cfg.Limits.MaxLogBatchSize))
		return
	}

	acceptedCount := 0
	for i := range batch.Entries {
		entry := &batch.Entries[i]
		if !isValidDecision(entry.Decision) {
			slog.Warn("skipping log entry with invalid decision", "decision", entry.Decision, "trace_id", entry.TraceID)
			continue
		}
		if s.cfg.Limits.MaxReasonBytes > 0 && len(entry.Reason) > s.cfg.Limits.MaxReasonBytes {
			slog.Warn("skipping log entry with oversized reason", "len", len(entry.Reason), "trace_id", entry.TraceID)
			continue
		}

		if s.decisionLog != nil {
			s.decisionLog.Log(entry)
		}
		acceptedCount++
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status": "accepted",
		"count":  acceptedCount,
	})
}

func isValidDecision(d string) bool {
	switch d {
	case "allow", "deny", "escalate", "workflow":
		return true
	default:
		return false
	}
}


func (s *Server) hasWorkflow() bool {
	_, isNoop := s.workflow.(*noopWorkflow)
	return !isNoop
}

func enrichedRequestChecks(req shared.EnrichedMCPRequest, limits LimitsConfig) []shared.FieldCheck {
	return []shared.FieldCheck{
		{Value: req.ServerName, Name: "server_name", Max: limits.MaxServerNameBytes},
		{Value: req.ToolName, Name: "tool_name", Max: limits.MaxToolNameBytes},
		{Value: req.TraceID, Name: "trace_id", Max: limits.MaxTraceIDBytes},
		{Value: req.SessionID, Name: "session_id", Max: limits.MaxSessionIDBytes},
	}
}

// validateClientHeaders checks that the forwarded headers do not exceed the
// resource limits defined in LimitsConfig. Returns an error if any limit is
// breached; the caller should respond with 400 Bad Request.
func validateClientHeaders(headers map[string][]string, limits LimitsConfig) error {
	if len(headers) == 0 {
		return nil
	}
	if limits.MaxForwardedHeaders > 0 && len(headers) > limits.MaxForwardedHeaders {
		return fmt.Errorf("too many forwarded headers: %d exceeds limit of %d", len(headers), limits.MaxForwardedHeaders)
	}
	totalBytes := 0
	for name, vals := range headers {
		if limits.MaxHeaderNameBytes > 0 && len(name) > limits.MaxHeaderNameBytes {
			return fmt.Errorf("forwarded header name %q exceeds maximum length of %d bytes", name, limits.MaxHeaderNameBytes)
		}
		totalBytes += len(name)
		for _, v := range vals {
			if limits.MaxHeaderValueBytes > 0 && len(v) > limits.MaxHeaderValueBytes {
				return fmt.Errorf("value for forwarded header %q exceeds maximum length of %d bytes", name, limits.MaxHeaderValueBytes)
			}
			totalBytes += len(v)
		}
	}
	if limits.MaxForwardedHeadersTotalBytes > 0 && totalBytes > limits.MaxForwardedHeadersTotalBytes {
		return fmt.Errorf("forwarded headers total size %d bytes exceeds limit of %d bytes", totalBytes, limits.MaxForwardedHeadersTotalBytes)
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func writeDeny(w http.ResponseWriter, reason, traceID string) {
	body := map[string]string{"error": reason}
	if traceID != "" {
		body["trace_id"] = traceID
	}
	writeJSON(w, http.StatusForbidden, body)
}

func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleReadyz(w http.ResponseWriter, r *http.Request) {
	tools, err := s.router.ListAllTools(r.Context())
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"status": "unavailable",
			"reason": err.Error(),
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status":            "ready",
		"tools":             len(tools),
		"signer_configured": s.signer != nil,
	})
}

func checkAPIVersion(v string) error {
	if v != "" && v != shared.APIVersion {
		return fmt.Errorf("unsupported api_version %q", v)
	}
	return nil
}

func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" || r.URL.Path == "/readyz" {
			next.ServeHTTP(w, r)
			return
		}

		mainEndpoint, ok := s.cfg.Server.Endpoints["main"]
		if !ok {
			writeError(w, http.StatusInternalServerError, "main endpoint misconfigured")
			return
		}
		auth := r.Header.Get("Authorization")
		expected := "Bearer " + mainEndpoint.Auth.Credentials.BearerToken

		if subtle.ConstantTimeCompare([]byte(auth), []byte(expected)) != 1 {
			writeError(w, http.StatusUnauthorized, "invalid or missing bearer token")
			return
		}

		next.ServeHTTP(w, r)
	})
}
