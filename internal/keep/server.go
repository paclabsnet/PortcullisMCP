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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/mitchellh/mapstructure"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/oauth2"

	"github.com/paclabsnet/PortcullisMCP/internal/keep/activitylog"
	"github.com/paclabsnet/PortcullisMCP/internal/shared"
	cfgloader "github.com/paclabsnet/PortcullisMCP/internal/shared/config"
	"github.com/paclabsnet/PortcullisMCP/internal/shared/middleware"
	"github.com/paclabsnet/PortcullisMCP/internal/shared/tlsutil"
	"github.com/paclabsnet/PortcullisMCP/internal/telemetry"
)

type keepCtxKey string

const clientHeadersKey keepCtxKey = "clientHeaders"
const rawTokenKey keepCtxKey = "rawToken"
const exchangedIdentityKey keepCtxKey = "exchangedIdentity"
const userIDKey keepCtxKey = "userID"
const oauthTokenKey keepCtxKey = "oauthToken"

// withClientHeaders returns a new context carrying the validated client headers.
func withClientHeaders(ctx context.Context, headers map[string][]string) context.Context {
	return context.WithValue(ctx, clientHeadersKey, headers)
}

// clientHeadersFromContext returns the client headers stored in ctx, or nil if absent.
func clientHeadersFromContext(ctx context.Context) map[string][]string {
	v, _ := ctx.Value(clientHeadersKey).(map[string][]string)
	return v
}

// withRawToken returns a new context carrying the user's raw identity token.
// The token must not be stored on any shared backend connection state — it must
// always flow through the per-request context to ensure multi-tenant safety.
func withRawToken(ctx context.Context, token string) context.Context {
	return context.WithValue(ctx, rawTokenKey, token)
}

// rawTokenFromContext returns the raw identity token from ctx, or "" if absent.
func rawTokenFromContext(ctx context.Context) string {
	v, _ := ctx.Value(rawTokenKey).(string)
	return v
}

// withExchangedIdentity returns a context carrying the post-exchange identity
// to inject. A nil identity signals fail-degraded: injection must be omitted.
func withExchangedIdentity(ctx context.Context, id *ExchangedIdentity) context.Context {
	return context.WithValue(ctx, exchangedIdentityKey, id)
}

// exchangedIdentityFromContext returns the identity to inject, or nil when
// exchange was either not configured, not yet applied, or failed.
func exchangedIdentityFromContext(ctx context.Context) *ExchangedIdentity {
	v, _ := ctx.Value(exchangedIdentityKey).(*ExchangedIdentity)
	return v
}

// withUserID returns a context carrying the authenticated user's ID for use by
// the Router when performing CredentialsStore lookups.
func withUserID(ctx context.Context, userID string) context.Context {
	return context.WithValue(ctx, userIDKey, userID)
}

// userIDFromContext returns the user ID stored in ctx, or "" if absent.
func userIDFromContext(ctx context.Context) string {
	v, _ := ctx.Value(userIDKey).(string)
	return v
}

// withOAuthToken returns a context carrying a resolved OAuth access token to be
// injected by the headerInjectingRoundTripper for the current backend call.
func withOAuthToken(ctx context.Context, accessToken string) context.Context {
	return context.WithValue(ctx, oauthTokenKey, accessToken)
}

// oauthTokenFromContext returns the OAuth access token, or "" if none was pre-fetched.
func oauthTokenFromContext(ctx context.Context) string {
	v, _ := ctx.Value(oauthTokenKey).(string)
	return v
}

// MCPRouter defines the interface for routing MCP tool calls to backends.
type MCPRouter interface {
	CallTool(ctx context.Context, serverName, toolName string, args map[string]any) (*mcp.CallToolResult, error)
	ListAllTools(ctx context.Context) ([]shared.AnnotatedTool, error)
	Reload(ctx context.Context, backends []BackendConfig) error
	// IsHiddenToolName reports real (pre-alias) tool names that must be
	// rejected as unknown. Required so the guard cannot be silently skipped.
	IsHiddenToolName(serverName, toolName string) bool
}

// Server is the portcullis-keep HTTP server.
type Server struct {
	cfg           Config
	pdp           PolicyDecisionPoint
	gateStaticPDP PolicyDecisionPoint
	router        MCPRouter
	credStore     CredentialsStore
	workflow      WorkflowHandler
	signer        *EscalationSigner
	activityLog   *activitylog.ActivityLogger
	normalizer    IdentityNormalizer
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

	staticCfg := cfg.Responsibility.GateStaticPolicy
	var gateStaticPDP PolicyDecisionPoint // nil means gate_static_policy is disabled
	switch staticCfg.Strategy {
	case "":
		// Not configured: leave nil. /config requests will return 404.
	case "noop":
		gateStaticPDP = NewNoopPDPClient()
	case "opa":
		gateStaticPDP = NewOPAClient(staticCfg.OPA.Endpoint)
	default:
		return nil, fmt.Errorf("unknown gate_static_policy strategy %q; supported: opa, noop", staticCfg.Strategy)
	}

	credStore := buildCredentialsStore(ctx, cfg)
	router := NewRouter(cfg.Responsibility.Backends, cfg.Operations.Storage)
	router.SetCredentialsStore(credStore)

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

	al := initActivityLogger(cfg)

	return &Server{
		cfg:           cfg,
		pdp:           pdp,
		gateStaticPDP: gateStaticPDP,
		router:        router,
		credStore:     credStore,
		workflow:      wf,
		signer:        signer,
		activityLog:   al,
		normalizer:    normalizer,
	}, nil
}

// initActivityLogger creates an ActivityLogger from Keep config, or returns nil
// if activity logging is disabled or initialization fails.
func initActivityLogger(cfg Config) *activitylog.ActivityLogger {
	if !cfg.MCPActivityLog.Enabled {
		return nil
	}
	al, err := activitylog.New(cfg.MCPActivityLog)
	if err != nil {
		slog.Warn("keep: failed to initialize activity log; audit logging disabled", "error", err)
		return nil
	}
	return al
}

// normalizedCall holds the result of the shared request entry pipeline:
// body decode, field validation, header validation, and identity normalization.
type normalizedCall struct {
	rawReq      shared.EnrichedMCPRequest
	principal   shared.Principal
	traceID     string
	remoteAddr  string
	bodyPreview string // non-empty only when capturePreview was true
	start       time.Time
}

// parseAndNormalize runs the shared entry pipeline for /call and /authorize:
//  1. Apply MaxBytesReader
//  2. Extract OTel trace context and start a child span (spanName)
//  3. Optionally tee the body into a capped preview buffer (capturePreview)
//  4. Decode into EnrichedMCPRequest; emit LogMalformed on parse error
//  5. Validate api_version and field lengths; emit LogMalformed on error
//  6. Validate forwarded client headers; emit LogMalformed on error
//  7. Resolve traceID and set span attributes
//  8. Normalize identity; log and respond on failure
//
// On success it returns (ctx, span, nc, true). The caller MUST call span.End().
// On failure it has already written an error response to w and returns false;
// the caller MUST still call span.End() (use defer span.End() unconditionally).
func (s *Server) parseAndNormalize(
	w http.ResponseWriter, r *http.Request,
	spanName string, capturePreview bool,
) (context.Context, trace.Span, normalizedCall, bool) {
	start := time.Now()

	if s.cfg.Limits.MaxRequestBodyBytes > 0 {
		r.Body = http.MaxBytesReader(w, r.Body, int64(s.cfg.Limits.MaxRequestBodyBytes))
	}

	ctx := otel.GetTextMapPropagator().Extract(r.Context(), propagation.HeaderCarrier(r.Header))
	ctx, span := otel.Tracer(shared.ServiceKeep).Start(ctx, spanName)

	var bodyBuf bytes.Buffer
	var bodyReader io.Reader = r.Body
	if capturePreview {
		previewCap := s.cfg.MCPActivityLog.MaxPayloadBytes
		if previewCap <= 0 {
			previewCap = cfgloader.DefaultMaxPayloadBytes
		}
		bodyReader = io.TeeReader(r.Body, &capWriter{buf: &bodyBuf, max: previewCap})
	}

	var rawReq shared.EnrichedMCPRequest
	if err := json.NewDecoder(bodyReader).Decode(&rawReq); err != nil {
		if s.activityLog != nil {
			s.activityLog.LogMalformed(activitylog.MalformedEntry{
				RemoteAddr: r.RemoteAddr,
				Error:      err.Error(),
				RawPreview: bodyBuf.String(),
			})
		}
		writeError(w, http.StatusBadRequest, "invalid request body")
		return ctx, span, normalizedCall{}, false
	}

	if err := checkAPIVersion(rawReq.APIVersion); err != nil {
		if s.activityLog != nil {
			s.activityLog.LogMalformed(activitylog.MalformedEntry{
				RemoteAddr: r.RemoteAddr,
				TraceID:    rawReq.TraceID,
				Error:      err.Error(),
				RawPreview: bodyBuf.String(),
			})
		}
		writeError(w, http.StatusBadRequest, err.Error())
		return ctx, span, normalizedCall{}, false
	}

	if err := shared.CheckFields(enrichedRequestChecks(rawReq, s.cfg.Limits)); err != nil {
		if s.activityLog != nil {
			s.activityLog.LogMalformed(activitylog.MalformedEntry{
				RemoteAddr: r.RemoteAddr,
				TraceID:    rawReq.TraceID,
				Error:      err.Error(),
				RawPreview: bodyBuf.String(),
			})
		}
		writeError(w, http.StatusBadRequest, err.Error())
		return ctx, span, normalizedCall{}, false
	}

	if err := validateClientHeaders(rawReq.ClientHeaders, s.cfg.Limits); err != nil {
		if s.activityLog != nil {
			s.activityLog.LogMalformed(activitylog.MalformedEntry{
				RemoteAddr: r.RemoteAddr,
				TraceID:    rawReq.TraceID,
				Error:      err.Error(),
				RawPreview: bodyBuf.String(),
			})
		}
		writeError(w, http.StatusBadRequest, err.Error())
		return ctx, span, normalizedCall{}, false
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

		var httpStatus int
		var clientMsg, respStatus string
		if verifyErr := (*shared.IdentityVerificationError)(nil); errors.As(normErr, &verifyErr) {
			httpStatus, clientMsg, respStatus = http.StatusUnauthorized, normErr.Error(), "denied"
		} else if validErr := (*NormalizationValidationError)(nil); errors.As(normErr, &validErr) {
			httpStatus, clientMsg, respStatus = http.StatusForbidden, normErr.Error(), "denied"
		} else {
			httpStatus, clientMsg, respStatus = http.StatusServiceUnavailable, "identity normalization failed", "backend_error"
		}

		if s.activityLog != nil {
			s.activityLog.LogRequest(activitylog.RequestEntry{
				SessionID:   rawReq.SessionID,
				TraceID:     traceID,
				RemoteAddr:  r.RemoteAddr,
				UserID:      rawReq.UserIdentity.UserID,
				Agent:       rawReq.Agent,
				ServerName:  rawReq.ServerName,
				ToolName:    rawReq.ToolName,
				Arguments:   rawReq.Arguments,
				PDPDecision: "error",
				PDPReason:   normErr.Error(),
			})
			s.activityLog.LogResponse(activitylog.ResponseEntry{
				SessionID:  rawReq.SessionID,
				TraceID:    traceID,
				RemoteAddr: r.RemoteAddr,
				UserID:     rawReq.UserIdentity.UserID,
				Agent:      rawReq.Agent,
				ServerName: rawReq.ServerName,
				ToolName:   rawReq.ToolName,
				DurationMS: time.Since(start).Milliseconds(),
				Status:     respStatus,
				Error:      normErr.Error(),
			})
		}
		writeError(w, httpStatus, clientMsg)
		return ctx, span, normalizedCall{}, false
	}
	span.SetAttributes(attribute.String("user.id", principal.UserID))

	return ctx, span, normalizedCall{
		rawReq:      rawReq,
		principal:   principal,
		traceID:     traceID,
		remoteAddr:  r.RemoteAddr,
		bodyPreview: bodyBuf.String(),
		start:       start,
	}, true
}

// buildCredentialsStore constructs the appropriate CredentialsStore for cfg.
// If Redis storage is configured it builds a Redis-backed store; otherwise it
// returns a MemoryCredentialsStore and warns if any backend uses OAuth.
func buildCredentialsStore(ctx context.Context, cfg Config) CredentialsStore {
	if cfg.Operations.Storage.Backend == "redis" {
		var redisCfg RedisConfig
		if err := decodeRedisConfig(cfg.Operations.Storage.Config, &redisCfg); err == nil {
			client, err := newKeepRedisClient(ctx, redisCfg)
			if err == nil {
				prefix := redisCfg.KeyPrefix
				if prefix == "" {
					prefix = defaultCredStorePrefix
				}
				return NewRedisCredentialsStore(client, prefix)
			}
			slog.Warn("keep: failed to connect Redis for CredentialsStore; falling back to memory store", "error", err)
		} else {
			slog.Warn("keep: failed to decode Redis config for CredentialsStore; falling back to memory store", "error", err)
		}
	}

	hasOAuthBackends := false
	for _, b := range cfg.Responsibility.Backends {
		if b.UserIdentity.Type == "oauth" {
			hasOAuthBackends = true
			break
		}
	}
	if hasOAuthBackends {
		slog.Warn("keep: backend OAuth state is process-local; restarts and failover will lose pending auth flows and tokens")
	}
	return NewMemoryCredentialsStore()
}

// Run starts the HTTPS server and blocks until ctx is cancelled.
func (s *Server) Run(ctx context.Context) error {
	// Populate the tool cache and initialize backend clients before accepting requests.
	// This is a hard failure: if a required dependency (e.g. Redis) is unavailable
	// the service must not start in a degraded state.
	if err := s.router.Reload(ctx, s.cfg.Responsibility.Backends); err != nil {
		return fmt.Errorf("startup: %w", err)
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
	mux.HandleFunc("GET /config/{resource}", s.handleGetConfig)
	// OAuth callback is intentionally unauthenticated: it is reached by the
	// user's browser after the authorization server redirects them back.
	mux.HandleFunc("GET /oauth/callback", s.handleOAuthCallback)

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
		if s.activityLog != nil {
			shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = s.activityLog.Shutdown(shutCtx)
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
	ctx, span, nc, ok := s.parseAndNormalize(w, r, "keep.evaluate", s.activityLog != nil)
	defer span.End()
	if !ok {
		return
	}

	rawReq, principal, traceID, remoteAddr, start := nc.rawReq, nc.principal, nc.traceID, nc.remoteAddr, nc.start

	if len(rawReq.ClientHeaders) > 0 {
		ctx = withClientHeaders(ctx, rawReq.ClientHeaders)
	}
	if rawReq.UserIdentity.RawToken != "" {
		ctx = withRawToken(ctx, rawReq.UserIdentity.RawToken)
	}
	if principal.UserID != "" {
		ctx = withUserID(ctx, principal.UserID)
	}

	// Reject the real name of an aliased tool before the PDP sees it: policy is
	// written against the alias, so the real name must look like an unknown tool.
	if s.router.IsHiddenToolName(rawReq.ServerName, rawReq.ToolName) {
		span.SetStatus(codes.Error, "unknown tool")
		slog.WarnContext(ctx, "call rejected: real name of aliased tool", "server", rawReq.ServerName, "tool", rawReq.ToolName, "trace_id", traceID)
		preMeta := activityMeta{
			sessionID: rawReq.SessionID, traceID: traceID, remoteAddr: remoteAddr,
			userID: principal.UserID, agent: rawReq.Agent,
			serverName: rawReq.ServerName, toolName: rawReq.ToolName,
		}
		s.logRequest(preMeta, rawReq.Arguments, "deny", "unknown tool", nil)
		s.logResponse(preMeta, start, "denied", "unknown tool", "", "", nil)
		writeDeny(w, "unknown tool", traceID)
		return
	}

	req := NewAuthorizedRequest(rawReq, principal)
	meta := newActivityMeta(req, rawReq.Agent, traceID, remoteAddr)

	pdpResp, err := s.pdp.Evaluate(ctx, req)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		slog.ErrorContext(ctx, "pdp evaluate failed", "error", err, "trace_id", traceID)
		s.logRequest(meta, req.Arguments, "error", err.Error(), nil)
		s.logResponse(meta, start, "backend_error", shared.ErrPDPUnavailable.Error(), "", "", nil)
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

	s.logRequest(meta, req.Arguments, pdpResp.Decision, pdpResp.Reason, escalationJTIs(req.EscalationTokens))

	switch pdpResp.Decision {
	case "allow":
		result, err := s.router.CallTool(ctx, req.ServerName, req.ToolName, req.Arguments)
		if err != nil {
			span.SetStatus(codes.Error, err.Error())
			slog.ErrorContext(ctx, "backend call failed", "error", err, "server", req.ServerName, "tool", req.ToolName, "trace_id", traceID)
			s.logResponse(meta, start, "backend_error", err.Error(), "", "", nil)
			writeError(w, http.StatusInternalServerError, "backend tool call failed")
			return
		}
		toolStatus, toolErr := "success", ""
		if result != nil && result.IsError {
			toolStatus, toolErr = "tool_error", "tool returned an error result"
		}
		s.logResponse(meta, start, toolStatus, toolErr, "", "", result)
		writeJSON(w, http.StatusOK, result)

	case "deny":
		span.SetStatus(codes.Error, "denied by policy")
		s.logResponse(meta, start, "denied", pdpResp.Reason, "", "", nil)
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
			s.logResponse(meta, start, "backend_error", "workflow submit failed: "+err.Error(), "", "", nil)
			writeError(w, http.StatusInternalServerError, "failed to submit escalation")
			return
		}
		if pendingJWT == "" && wfRef == "" {
			span.SetStatus(codes.Error, "escalation misconfigured")
			slog.ErrorContext(ctx, "escalation required but no approval mechanism available",
				"tool", req.ToolName, "user", req.Principal.UserID, "trace_id", traceID)
			s.logResponse(meta, start, "backend_error", "escalation required but no approval mechanism is available", "", "", nil)
			writeError(w, http.StatusInternalServerError, "escalation required but no approval mechanism is available")
			return
		}
		s.logResponse(meta, start, "escalation_pending", "", escalationJTI, wfRef, nil)
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
			s.logResponse(meta, start, "denied", "workflow required but not configured", "", "", nil)
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
			s.logResponse(meta, start, "backend_error", "workflow submit failed: "+err.Error(), "", "", nil)
			writeError(w, http.StatusInternalServerError, "failed to submit workflow request")
			return
		}
		if pendingJWT == "" && wfRef == "" {
			span.SetStatus(codes.Error, "workflow misconfigured")
			s.logResponse(meta, start, "backend_error", "workflow required but no approval mechanism is available", "", "", nil)
			writeError(w, http.StatusInternalServerError, "workflow required but no approval mechanism is available")
			return
		}
		s.logResponse(meta, start, "workflow_pending", "", escalationJTI, wfRef, nil)
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
		s.logResponse(meta, start, "denied", "unknown pdp decision", "", "", nil)
		writeDeny(w, "unknown pdp decision — denied by default", traceID)
	}
}

// handleAuthorize evaluates the PDP for a gate-local tool call.
func (s *Server) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	ctx, span, nc, ok := s.parseAndNormalize(w, r, "keep.authorize", false)
	defer span.End()
	if !ok {
		return
	}

	rawReq, principal, traceID, remoteAddr, start := nc.rawReq, nc.principal, nc.traceID, nc.remoteAddr, nc.start
	req := NewAuthorizedRequest(rawReq, principal)
	meta := newActivityMeta(req, rawReq.Agent, traceID, remoteAddr)

	pdpResp, err := s.pdp.Evaluate(ctx, req)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		slog.ErrorContext(ctx, "pdp evaluate failed", "error", err, "trace_id", traceID)
		s.logRequest(meta, req.Arguments, "error", err.Error(), nil)
		s.logResponse(meta, start, "backend_error", shared.ErrPDPUnavailable.Error(), "", "", nil)
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

	s.logRequest(meta, req.Arguments, pdpResp.Decision, pdpResp.Reason, escalationJTIs(req.EscalationTokens))

	switch pdpResp.Decision {
	case "allow":
		s.logResponse(meta, start, "success", "", "", "", nil)
		writeJSON(w, http.StatusOK, pdpResp)
	case "deny":
		span.SetStatus(codes.Error, "denied by policy")
		s.logResponse(meta, start, "denied", pdpResp.Reason, "", "", nil)
		writeDeny(w, pdpResp.Reason, traceID)
	case "escalate":
		pendingJWT := ""
		escalationJTI := ""
		if s.signer != nil {
			var signErr error
			pendingJWT, escalationJTI, signErr = s.signer.Sign(req, pdpResp.Reason, pdpResp.EscalationScope)
			if signErr != nil {
				slog.ErrorContext(ctx, "escalation jwt sign failed", "error", signErr, "trace_id", traceID)
			}
		}
		wfRef, wfErr := s.workflow.Submit(ctx, req, pendingJWT)
		if wfErr != nil {
			span.SetStatus(codes.Error, wfErr.Error())
			slog.ErrorContext(ctx, "workflow submit failed", "error", wfErr, "trace_id", traceID)
			s.logResponse(meta, start, "backend_error", "workflow submit failed: "+wfErr.Error(), "", "", nil)
			writeError(w, http.StatusInternalServerError, "failed to submit escalation")
			return
		}
		s.logResponse(meta, start, "escalation_pending", "", escalationJTI, wfRef, nil)
		writeJSON(w, http.StatusAccepted, map[string]string{
			"status":             "escalation_pending",
			"reason":             pdpResp.Reason,
			"workflow_reference": wfRef,
			"escalation_jti":     escalationJTI,
			"pending_jwt":        pendingJWT,
			"trace_id":           traceID,
		})
	default:
		span.SetStatus(codes.Error, "unknown decision")
		s.logResponse(meta, start, "denied", "unknown pdp decision", "", "", nil)
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

// handleGetConfig fetches a static tool configuration from the gate_static_policy PDP.
// The PDP is responsible for deciding which resources are served; unknown resources
// receive an empty policy ({}) rather than an error.
func (s *Server) handleGetConfig(w http.ResponseWriter, r *http.Request) {
	if s.gateStaticPDP == nil {
		http.Error(w, "gate_static_policy is not configured on this Keep instance", http.StatusNotFound)
		return
	}

	resource := r.PathValue("resource")

	slog.Info("keep: gate_static_policy request received", "resource", resource)

	cfg, err := s.gateStaticPDP.GetStaticPolicy(r.Context(), resource)
	if err != nil {
		slog.Error("keep: gate_static_policy fetch failed", "resource", resource, "error", err)
		http.Error(w, "failed to fetch config", http.StatusInternalServerError)
		return
	}

	if string(cfg) == "{}" || len(cfg) == 0 {
		slog.Warn("keep: gate_static_policy returned empty policy — resource may be missing from PDP data", "resource", resource)
	} else {
		slog.Info("keep: gate_static_policy served", "resource", resource)
	}

	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(cfg)
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
	body := map[string]any{
		"status":            "ready",
		"tools":             len(tools),
		"signer_configured": s.signer != nil,
	}
	if s.activityLog != nil {
		body["activity_log"] = s.activityLog.Stats()
	}
	writeJSON(w, http.StatusOK, body)
}

func checkAPIVersion(v string) error {
	if v != "" && v != shared.APIVersion {
		return fmt.Errorf("unsupported api_version %q", v)
	}
	return nil
}

// handleOAuthCallback receives the authorization code from the OAuth provider
// after the user completes the browser-based consent flow.
func (s *Server) handleOAuthCallback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	errParam := r.URL.Query().Get("error")
	if errParam != "" {
		errDesc := r.URL.Query().Get("error_description")
		slog.Warn("keep: OAuth callback received error from provider", "error", errParam, "description", errDesc)
		http.Error(w, "authorization failed: "+errParam, http.StatusBadRequest)
		return
	}

	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")
	if code == "" || state == "" {
		http.Error(w, "missing required code or state parameters", http.StatusBadRequest)
		return
	}

	pending, err := s.credStore.ConsumePending(ctx, state)
	if err != nil {
		slog.Error("keep: OAuth callback: failed to consume pending state", "error", err)
		http.Error(w, "internal error processing OAuth state", http.StatusInternalServerError)
		return
	}
	if pending == nil {
		http.Error(w, "invalid or expired OAuth state — the authorization flow may have timed out or already completed", http.StatusBadRequest)
		return
	}

	token, err := s.exchangeOAuthCode(ctx, pending, code)
	if err != nil {
		slog.Error("keep: OAuth callback: code exchange failed", "error", err, "backend", pending.BackendName)
		http.Error(w, "token exchange failed", http.StatusInternalServerError)
		return
	}

	// Honour StoreRefreshTokens setting: strip the refresh token if not configured.
	if oauthCfg := s.backendOAuthConfig(pending.BackendName); oauthCfg != nil && !oauthCfg.StoreRefreshTokens {
		token.RefreshToken = ""
	}

	if err := s.credStore.SetToken(ctx, pending.BackendName, pending.UserID, token); err != nil {
		slog.Error("keep: OAuth callback: failed to store token", "error", err, "backend", pending.BackendName)
		http.Error(w, "failed to store token", http.StatusInternalServerError)
		return
	}

	slog.Info("keep: OAuth token stored after successful callback", "backend", pending.BackendName, "user_id", pending.UserID)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, "<html><body><p>Authorization successful. You may close this window and retry your request.</p></body></html>")
}

// exchangeOAuthCode performs the authorization-code-for-token exchange using PKCE.
// It resolves the client secret and token_endpoint_auth_method from the
// CredentialsStore (for dynamically registered clients) and applies the
// appropriate authentication method per RFC 7591.
func (s *Server) exchangeOAuthCode(ctx context.Context, pending *pendingAuth, code string) (*userToken, error) {
	clientID := pending.ClientID
	clientSecret := ""
	authMethod := "client_secret_basic" // RFC 7591 default

	// Prefer dynamic client credentials stored after DCR.
	if reg, err := s.credStore.GetClientReg(ctx, pending.BackendName); err == nil && reg != nil {
		slog.Debug("keep: token exchange using dynamic client registration",
			"backend", pending.BackendName,
			"client_id", reg.ClientID,
			"token_endpoint_auth_method", reg.TokenEndpointAuthMethod,
			"has_secret", reg.ClientSecret != "",
		)
		clientID = reg.ClientID
		clientSecret = reg.ClientSecret
		if reg.TokenEndpointAuthMethod != "" {
			authMethod = reg.TokenEndpointAuthMethod
		}
	} else {
		slog.Debug("keep: token exchange using static client credentials",
			"backend", pending.BackendName,
			"client_id", clientID,
		)
	}

	slog.Debug("keep: token exchange request",
		"backend", pending.BackendName,
		"token_endpoint", pending.TokenEndpoint,
		"client_id", clientID,
		"auth_method", authMethod,
		"redirect_uri", pending.RedirectURI,
		"resource", pending.Resource,
	)

	endpoint := oauth2.Endpoint{
		TokenURL: pending.TokenEndpoint,
	}

	// Select the auth style based on the token_endpoint_auth_method.
	switch authMethod {
	case "client_secret_post":
		endpoint.AuthStyle = oauth2.AuthStyleInParams
	case "none":
		// Public client; no secret.
		clientSecret = ""
		endpoint.AuthStyle = oauth2.AuthStyleInParams
	default: // "client_secret_basic" and any unknown method (fallback)
		endpoint.AuthStyle = oauth2.AuthStyleInHeader
	}

	oauthCfg := &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  pending.RedirectURI,
		Endpoint:     endpoint,
	}
	exchangeOpts := []oauth2.AuthCodeOption{
		oauth2.SetAuthURLParam("code_verifier", pending.CodeVerifier),
	}
	if pending.Resource != "" {
		exchangeOpts = append(exchangeOpts, oauth2.SetAuthURLParam("resource", pending.Resource)) // RFC 8707
	}
	tok, err := oauthCfg.Exchange(ctx, code, exchangeOpts...)
	if err != nil {
		// Surface the raw token endpoint response body when available.
		var retrieveErr *oauth2.RetrieveError
		if errors.As(err, &retrieveErr) {
			slog.Debug("keep: token exchange failed",
				"backend", pending.BackendName,
				"http_status", retrieveErr.Response.StatusCode,
				"response_body", string(retrieveErr.Body),
				"error", err,
			)
		} else {
			slog.Debug("keep: token exchange failed", "backend", pending.BackendName, "error", err)
		}
		return nil, fmt.Errorf("oauth exchange: %w", err)
	}

	ut := &userToken{
		AccessToken:   tok.AccessToken,
		RefreshToken:  tok.RefreshToken,
		Expiry:        tok.Expiry,
		TokenEndpoint: pending.TokenEndpoint,
	}
	slog.Debug("keep: token exchange succeeded",
		"backend", pending.BackendName,
		"expiry", tok.Expiry,
		"expiry_is_zero", tok.Expiry.IsZero(),
		"has_refresh_token", tok.RefreshToken != "",
	)
	debugLogBearerToken("keep: token exchange← access token", tok.AccessToken, "backend", pending.BackendName)
	if tok.RefreshToken != "" {
		debugLogBearerToken("keep: token exchange← refresh token", tok.RefreshToken, "backend", pending.BackendName)
	}
	return ut, nil
}

// backendOAuthConfig returns the BackendOAuth config for the named backend,
// or nil if not found or not an OAuth backend.
func (s *Server) backendOAuthConfig(name string) *BackendOAuth {
	for i := range s.cfg.Responsibility.Backends {
		b := &s.cfg.Responsibility.Backends[i]
		if b.Name == name && b.UserIdentity.Type == "oauth" {
			cfg := b.UserIdentity.OAuth
			return &cfg
		}
	}
	return nil
}

// decodeRedisConfig decodes the StorageConfig.Config map into a RedisConfig.
func decodeRedisConfig(raw map[string]interface{}, out *RedisConfig) error {
	return mapstructure.Decode(raw, out)
}

// escalationJTIs returns the TokenID of every escalation token in the slice.
// Logging all JTIs rather than just the first allows an analyst to join a retry
// mcp_request with any of the escalation_pending mcp_responses that issued
// them, and to reconstruct multi-step approval chains. Returns nil when empty.
func escalationJTIs(tokens []shared.EscalationToken) []string {
	if len(tokens) == 0 {
		return nil
	}
	jtis := make([]string, len(tokens))
	for i, t := range tokens {
		jtis[i] = t.TokenID
	}
	return jtis
}

// capWriter is an io.Writer that accepts at most max bytes into buf, silently
// discarding the rest. It always reports success so it never interrupts the
// io.TeeReader wrapping it. Used to bound the preview buffer in handleCall.
type capWriter struct {
	buf *bytes.Buffer
	max int
}

func (c *capWriter) Write(p []byte) (int, error) {
	if rem := c.max - c.buf.Len(); rem > 0 {
		if len(p) > rem {
			p = p[:rem]
		}
		c.buf.Write(p) //nolint:errcheck // bytes.Buffer.Write never returns an error
	}
	return len(p), nil
}

func (s *Server) authMiddleware(next http.Handler) http.Handler {
	mainEndpoint := s.cfg.Server.Endpoints["main"]
	return middleware.BearerAuth(middleware.AuthConfig{
		BearerToken: mainEndpoint.Auth.Credentials.BearerToken,
		SkipPaths:   []string{"/healthz", "/readyz", "/oauth/callback"},
		Realm:       "portcullis-keep",
	})(next)
}
