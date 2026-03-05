package gate

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/paclabsnet/PortcullisMCP/internal/shared"
)

// Forwarder sends enriched MCP requests to portcullis-keep and returns the result.
type Forwarder struct {
	cfg    KeepConfig
	client *http.Client
}

// NewForwarder creates a Forwarder configured for the given Keep endpoint.
func NewForwarder(cfg KeepConfig) (*Forwarder, error) {
	transport, err := buildTransport(cfg.Auth)
	if err != nil {
		return nil, fmt.Errorf("build keep transport: %w", err)
	}
	return &Forwarder{
		cfg:    cfg,
		client: &http.Client{Transport: transport},
	}, nil
}

// CallTool forwards a tool call to Keep and returns the MCP result.
func (f *Forwarder) CallTool(ctx context.Context, req shared.EnrichedMCPRequest) (*mcp.CallToolResult, error) {
	var result mcp.CallToolResult
	if err := f.post(ctx, "/call", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// ListTools fetches the aggregated tool list from Keep.
func (f *Forwarder) ListTools(ctx context.Context, identity shared.UserIdentity, escalationTokens []shared.EscalationToken) ([]*mcp.Tool, error) {
	reqBody := struct {
		UserIdentity     shared.UserIdentity      `json:"user_identity"`
		EscalationTokens []shared.EscalationToken `json:"escalation_tokens"`
	}{
		UserIdentity:     identity,
		EscalationTokens: escalationTokens,
	}
	var tools []*mcp.Tool
	if err := f.post(ctx, "/tools", reqBody, &tools); err != nil {
		return nil, err
	}
	return tools, nil
}

// SendLogs sends a batch of decision log entries to Keep.
// This is best-effort — errors are logged but not returned.
func (f *Forwarder) SendLogs(ctx context.Context, entries []DecisionLogEntry) error {
	if len(entries) == 0 {
		return nil
	}
	var result map[string]interface{}
	return f.post(ctx, "/log", entries, &result)
}

func (f *Forwarder) post(ctx context.Context, path string, body, out any) error {
	data, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("marshal request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, f.cfg.Endpoint+path, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("build http request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if f.cfg.Auth.Type == "bearer" && f.cfg.Auth.Token != "" {
		req.Header.Set("Authorization", "Bearer "+f.cfg.Auth.Token)
	}

	resp, err := f.client.Do(req)
	if err != nil {
		return fmt.Errorf("keep request: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK, http.StatusCreated:
		return json.NewDecoder(resp.Body).Decode(out)
	case http.StatusForbidden:
		return shared.ErrDenied
	case http.StatusAccepted:
		return shared.ErrEscalationPending
	case http.StatusServiceUnavailable:
		return shared.ErrPDPUnavailable
	default:
		var errBody struct {
			Error string `json:"error"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&errBody)
		return fmt.Errorf("keep returned %d: %s", resp.StatusCode, errBody.Error)
	}
}

// buildTransport constructs an http.RoundTripper based on the auth config.
func buildTransport(auth KeepAuth) (http.RoundTripper, error) {
	base := http.DefaultTransport.(*http.Transport).Clone()
	if base.TLSClientConfig == nil {
		base.TLSClientConfig = &tls.Config{}
	}

	// Load a custom server CA for verifying Keep's TLS certificate.
	// Required when Keep uses a private or enterprise CA not in the system pool.
	if auth.ServerCA != "" {
		caData, err := os.ReadFile(auth.ServerCA)
		if err != nil {
			return nil, fmt.Errorf("read keep server CA: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caData) {
			return nil, fmt.Errorf("parse keep server CA: no valid certificates found")
		}
		base.TLSClientConfig.RootCAs = pool
	}

	if auth.Type == "mtls" {
		if auth.Cert == "" || auth.Key == "" {
			return nil, fmt.Errorf("mtls auth requires cert and key")
		}
		cert, err := tls.LoadX509KeyPair(auth.Cert, auth.Key)
		if err != nil {
			return nil, fmt.Errorf("load mtls keypair: %w", err)
		}
		base.TLSClientConfig.Certificates = []tls.Certificate{cert}
	}

	return base, nil
}
