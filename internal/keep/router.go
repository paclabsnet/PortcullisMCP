package keep

import (
	"context"
	"fmt"
	"os/exec"
	"sync"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// MCPBackend routes tool calls to a registered MCP backend server.
type MCPBackend interface {
	CallTool(ctx context.Context, serverName, toolName string, args map[string]any) (*mcp.CallToolResult, error)
	ListTools(ctx context.Context, serverName string) ([]*mcp.Tool, error)
}

// Router maintains MCP client sessions to all registered backend servers.
type Router struct {
	mu       sync.Mutex
	backends map[string]*backendConn
}

type backendConn struct {
	cfg     BackendConfig
	client  *mcp.Client
	session *mcp.ClientSession
}

// NewRouter creates a Router from the backend configs but does not yet connect.
// Connections are established lazily on first use.
func NewRouter(backends map[string]BackendConfig) *Router {
	r := &Router{
		backends: make(map[string]*backendConn, len(backends)),
	}
	for name, cfg := range backends {
		r.backends[name] = &backendConn{cfg: cfg}
	}
	return r
}

// CallTool routes a tool call to the named backend server.
func (r *Router) CallTool(ctx context.Context, serverName, toolName string, args map[string]any) (*mcp.CallToolResult, error) {
	session, err := r.sessionFor(ctx, serverName)
	if err != nil {
		return nil, err
	}
	return session.CallTool(ctx, &mcp.CallToolParams{
		Name:      toolName,
		Arguments: args,
	})
}

// ListTools returns all tools exposed by the named backend server.
func (r *Router) ListTools(ctx context.Context, serverName string) ([]*mcp.Tool, error) {
	session, err := r.sessionFor(ctx, serverName)
	if err != nil {
		return nil, err
	}
	resp, err := session.ListTools(ctx, &mcp.ListToolsParams{})
	if err != nil {
		return nil, fmt.Errorf("list tools from %q: %w", serverName, err)
	}
	return resp.Tools, nil
}

// ListAllTools returns the aggregated tool list from all registered backends.
// Each returned tool is annotated with its server name via a naming convention
// (serverName + "." + toolName) so that gate can infer routing on CallTool.
// Tools that fail to list are skipped with a warning.
func (r *Router) ListAllTools(ctx context.Context) ([]*mcp.Tool, error) {
	r.mu.Lock()
	names := make([]string, 0, len(r.backends))
	for name := range r.backends {
		names = append(names, name)
	}
	r.mu.Unlock()

	var all []*mcp.Tool
	for _, name := range names {
		tools, err := r.ListTools(ctx, name)
		if err != nil {
			// Non-fatal: log and continue so one broken backend doesn't
			// prevent the gate from starting.
			continue
		}
		all = append(all, tools...)
	}
	return all, nil
}

// sessionFor returns an active MCP client session for the named backend,
// establishing the connection if it does not yet exist.
func (r *Router) sessionFor(ctx context.Context, serverName string) (*mcp.ClientSession, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	conn, ok := r.backends[serverName]
	if !ok {
		return nil, fmt.Errorf("unknown backend %q", serverName)
	}
	if conn.session != nil {
		return conn.session, nil
	}

	transport, err := buildBackendTransport(conn.cfg)
	if err != nil {
		return nil, fmt.Errorf("build transport for %q: %w", serverName, err)
	}

	conn.client = mcp.NewClient(&mcp.Implementation{
		Name:    "portcullis-keep",
		Version: "0.1.0",
	}, nil)

	session, err := conn.client.Connect(ctx, transport, nil)
	if err != nil {
		return nil, fmt.Errorf("connect to backend %q: %w", serverName, err)
	}
	conn.session = session
	return session, nil
}

// buildBackendTransport creates the appropriate MCP transport for a backend.
func buildBackendTransport(cfg BackendConfig) (mcp.Transport, error) {
	switch cfg.Type {
	case "stdio":
		if cfg.Command == "" {
			return nil, fmt.Errorf("stdio backend requires a command")
		}
		cmd := exec.Command(cfg.Command, cfg.Args...)
		for k, v := range cfg.Env {
			cmd.Env = append(cmd.Env, k+"="+v)
		}
		return &mcp.CommandTransport{Command: cmd}, nil
	default:
		return nil, fmt.Errorf("unsupported backend type %q", cfg.Type)
	}
}
