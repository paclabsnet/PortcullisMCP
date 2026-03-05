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
	ListAllTools(ctx context.Context) ([]*mcp.Tool, error)
}

// Server is the portcullis-keep HTTP server.
// It receives enriched MCP requests from portcullis-gate instances, calls the
// PDP, and either routes the call to a backend MCP server, returns a deny, or
// submits an escalation to the enterprise workflow system.
type Server struct {
	cfg         Config
	pdp         PolicyDecisionPoint
	router      MCPRouter
	workflow    WorkflowHandler
	decisionLog *DecisionLogger
}

// NewServer creates a Keep server. All dependencies are injected.
func NewServer(cfg Config) (*Server, error) {
	pdp := NewOPAClient(cfg.PDP.Endpoint)

	router := NewRouter(cfg.Backends)

	wf, err := NewWorkflowHandler(cfg.Escalation.Workflow)
	if err != nil {
		return nil, fmt.Errorf("create workflow handler: %w", err)
	}

	return &Server{
		cfg:         cfg,
		pdp:         pdp,
		router:      router,
		workflow:    wf,
		decisionLog: NewDecisionLogger(cfg.DecisionLog),
	}, nil
}

// Run starts the HTTPS server and blocks until ctx is cancelled.
func (s *Server) Run(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /call", s.handleCall)
	mux.HandleFunc("POST /tools", s.handleListTools)
	mux.HandleFunc("POST /log", s.handleLog)

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
			writeError(w, http.StatusInternalServerError, fmt.Sprintf("backend call failed: %s", err))
			return
		}
		writeJSON(w, http.StatusOK, result)

	case "deny":
		writeError(w, http.StatusForbidden, pdpResp.Reason)

	case "escalate":
		wfRequestID, err := s.workflow.Submit(r.Context(), req, pdpResp.Reason)
		if err != nil {
			slog.Error("workflow submit failed", "error", err, "request_id", req.RequestID)
			writeError(w, http.StatusInternalServerError, "escalation submission failed")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"status":              "escalation_pending",
			"reason":              pdpResp.Reason,
			"workflow_request_id": wfRequestID,
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
