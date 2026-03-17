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
	"github.com/paclabsnet/PortcullisMCP/internal/shared"
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
}

// NewServer creates a Keep server. configPath is retained so the admin reload
// handler can re-read the file on demand.
func NewServer(cfg Config, configPath string) (*Server, error) {
	pdp := NewOPAClient(cfg.PDP.Endpoint)

	router := NewRouter(cfg.Backends)

	wf, err := NewWorkflowHandler(cfg.Escalation.Workflow)
	if err != nil {
		return nil, fmt.Errorf("create workflow handler: %w", err)
	}

	signer, err := NewEscalationSigner(cfg.EscalationRequestSigning)
	if err != nil {
		return nil, fmt.Errorf("create escalation signer: %w", err)
	}

	return &Server{
		cfg:         cfg,
		configPath:  configPath,
		pdp:         pdp,
		router:      router,
		workflow:    wf,
		signer:      signer,
		decisionLog: NewDecisionLogger(cfg.DecisionLog),
	}, nil
}

// Run starts the HTTPS server and blocks until ctx is cancelled.
func (s *Server) Run(ctx context.Context) error {
	// Populate the tool cache before accepting requests.
	if err := s.router.Reload(ctx, s.cfg.Backends); err != nil {
		slog.Warn("initial tool cache population failed", "error", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /call", s.handleCall)
	mux.HandleFunc("POST /tools", s.handleListTools)
	mux.HandleFunc("POST /log", s.handleLog)
	mux.HandleFunc("POST /admin/reload", s.adminAuthMiddleware(s.handleReload))

	// Wrap with authentication middleware if bearer token is configured
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
	var req shared.EnrichedMCPRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	pdpResp, err := s.pdp.Evaluate(r.Context(), req)
	if err != nil {
		slog.Error("pdp evaluate failed", "error", err, "request_id", req.RequestID)
		writeError(w, http.StatusServiceUnavailable, shared.ErrPDPUnavailable.Error())
		return
	}

	slog.Info("pdp decision",
		"decision", pdpResp.Decision,
		"tool", req.ToolName,
		"user", req.UserIdentity.UserID,
		"request_id", req.RequestID,
	)

	// Log the decision
	s.decisionLog.Log(&DecisionLogEntry{
		SessionID:    req.SessionID,
		RequestID:    req.RequestID,
		UserID:       req.UserIdentity.UserID,
		ServerName:   req.ServerName,
		ToolName:     req.ToolName,
		Decision:     pdpResp.Decision,
		Reason:       pdpResp.Reason,
		PDPRequestID: pdpResp.RequestID,
		Source:       "pdp",
		Arguments:    req.Arguments,
	})

	switch pdpResp.Decision {
	case "allow":
		result, err := s.router.CallTool(r.Context(), req.ServerName, req.ToolName, req.Arguments)
		if err != nil {
			slog.Error("backend call failed", "error", err, "server", req.ServerName, "tool", req.ToolName, "request_id", req.RequestID)
			writeError(w, http.StatusInternalServerError, fmt.Sprintf("backend call failed: %s", err))
			return
		}
		writeJSON(w, http.StatusOK, result)

	case "deny":
		writeError(w, http.StatusForbidden, pdpResp.Reason)

	case "escalate":
		escalationJWT := ""
		if s.signer != nil {
			jwtStr, err := s.signer.Sign(req, pdpResp.Reason, pdpResp.EscalationScope)
			if err != nil {
				slog.Error("escalation jwt sign failed", "error", err, "request_id", req.RequestID)
				// Non-fatal: continue without JWT; some workflow handlers may still function.
			} else {
				escalationJWT = jwtStr
			}
		}
		wfRef, err := s.workflow.Submit(r.Context(), req, escalationJWT)
		if err != nil {
			slog.Error("workflow submit failed", "error", err, "request_id", req.RequestID)
			writeError(w, http.StatusInternalServerError, "escalation submission failed")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"status":             "escalation_pending",
			"reason":             pdpResp.Reason,
			"workflow_reference": wfRef,
		})

	default:
		slog.Error("unknown pdp decision", "decision", pdpResp.Decision, "request_id", req.RequestID)
		writeError(w, http.StatusForbidden, "unknown pdp decision — denied by default")
	}
}

// handleListTools returns the aggregated tool list from all backends.
func (s *Server) handleListTools(w http.ResponseWriter, r *http.Request) {
	tools, err := s.router.ListAllTools(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("list tools failed: %s", err))
		return
	}
	writeJSON(w, http.StatusOK, tools)
}

// handleLog receives decision log entries from portcullis-gate instances
// for fast-path decisions and queues them for batched forwarding.
func (s *Server) handleLog(w http.ResponseWriter, r *http.Request) {
	var entries []DecisionLogEntry
	if err := json.NewDecoder(r.Body).Decode(&entries); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Queue all entries to the decision logger
	for i := range entries {
		s.decisionLog.Log(&entries[i])
	}

	writeJSON(w, http.StatusAccepted, map[string]interface{}{
		"status": "accepted",
		"count":  len(entries),
	})
}

// adminAuthMiddleware guards admin endpoints with the X-Api-Key header.
func (s *Server) adminAuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.cfg.Admin.Token == "" {
			writeError(w, http.StatusForbidden, "admin API not configured")
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
	cfg, err := LoadConfig(s.configPath)
	if err != nil {
		slog.Error("admin reload: read config failed", "error", err)
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("read config: %s", err))
		return
	}
	if err := s.router.Reload(r.Context(), cfg.Backends); err != nil {
		slog.Error("admin reload: backend reload failed", "error", err)
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("reload backends: %s", err))
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

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// authMiddleware validates the bearer token if configured.
func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
