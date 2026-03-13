package gate

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/paclabsnet/PortcullisMCP/internal/gate/localfs"
	"github.com/paclabsnet/PortcullisMCP/internal/shared"
)

// DecisionLogEntry is a fast-path decision log entry sent to Keep.
type DecisionLogEntry struct {
	Timestamp time.Time      `json:"timestamp"`
	SessionID string         `json:"session_id"`
	RequestID string         `json:"request_id"`
	UserID    string         `json:"user_id"`
	ToolName  string         `json:"tool_name"`
	Decision  string         `json:"decision"` // "allow" | "deny"
	Reason    string         `json:"reason"`
	Source    string         `json:"source"` // always "gate-fastpath"
	Arguments map[string]any `json:"arguments,omitempty"`
}

// Gate is the portcullis-gate MCP proxy server.
// It presents itself to the agent as an MCP server, applies the local
// fast-path for filesystem operations, and forwards everything else to Keep.
type Gate struct {
	cfg           Config
	identity      *IdentityCache
	store         *TokenStore
	forwarder     *Forwarder
	server        *mcp.Server
	localFS       *mcp.ClientSession // in-process filesystem backend
	sessionID     string
	toolServerMap map[string]string // tool name → backend server name, populated at startup
	logChan       chan DecisionLogEntry
	logDone       chan struct{}
	logWg         sync.WaitGroup
}

// New creates a Gate from the given config. Call Run to start serving.
func New(ctx context.Context, cfg Config) (*Gate, error) {
	identity, err := NewIdentityCache(ctx, cfg.Identity)
	if err != nil {
		return nil, fmt.Errorf("resolve identity: %w", err)
	}

	storePath := cfg.TokenStore
	if storePath == "" {
		storePath = "~/.portcullis/tokens.json"
	}
	store, err := NewTokenStore(ctx, storePath)
	if err != nil {
		return nil, fmt.Errorf("open token store: %w", err)
	}

	fwd, err := NewForwarder(cfg.Keep)
	if err != nil {
		return nil, fmt.Errorf("create forwarder: %w", err)
	}

	// Start the in-process local filesystem server if a sandbox is configured.
	var localFSSession *mcp.ClientSession
	if cfg.Sandbox.Directory != "" {
		expanded, err := expandHome(cfg.Sandbox.Directory)
		if err != nil {
			return nil, fmt.Errorf("expand sandbox dir: %w", err)
		}
		localFSSession, err = localfs.Connect(ctx, expanded)
		if err != nil {
			return nil, fmt.Errorf("start local filesystem server: %w", err)
		}
	}

	g := &Gate{
		cfg:           cfg,
		identity:      identity,
		store:         store,
		forwarder:     fwd,
		localFS:       localFSSession,
		sessionID:     uuid.New().String(),
		toolServerMap: make(map[string]string),
		logChan:       make(chan DecisionLogEntry, 1000),
		logDone:       make(chan struct{}),
	}

	// Start decision log worker
	g.logWg.Add(1)
	go g.logWorker()

	// Fetch tool schemas from Keep and register them with the MCP server.
	// Local filesystem tools are also registered so the agent sees them.
	g.server = mcp.NewServer(&mcp.Implementation{
		Name:    "portcullis-gate",
		Version: "0.1.0",
	}, nil)

	if localFSSession != nil {
		localTools, err := localFSSession.ListTools(ctx, &mcp.ListToolsParams{})
		if err != nil {
			return nil, fmt.Errorf("list local filesystem tools: %w", err)
		}
		for _, tool := range localTools.Tools {
			g.registerTool(tool)
		}
	}

	keepTools, err := fwd.ListTools(ctx, identity.Get(ctx), store.All())
	if err != nil {
		// Non-fatal: gate can still serve local filesystem tools if Keep is
		// temporarily unavailable at startup.
		slog.Warn("fetch tool list from keep failed", "error", err)
	}
	for _, at := range keepTools {
		g.toolServerMap[at.Tool.Name] = at.ServerName
		g.registerTool(at.Tool)
	}

	return g, nil
}

// Run starts the MCP server on stdio transport and blocks until ctx is
// cancelled or the transport closes.
func (g *Gate) Run(ctx context.Context) error {
	mgmt := NewManagementServer(g.store, g.identity, g.cfg.ManagementAPI)
	if err := mgmt.Start(ctx); err != nil {
		return fmt.Errorf("start management api: %w", err)
	}

	// Shutdown decision log worker on context cancellation
	go func() {
		<-ctx.Done()
		close(g.logDone)
		g.logWg.Wait() // Wait for worker to flush and exit
	}()

	return g.server.Run(ctx, &mcp.StdioTransport{})
}

// registerTool adds a single tool to the MCP server with a forwarding handler.
func (g *Gate) registerTool(tool *mcp.Tool) {
	mcp.AddTool(g.server, tool, func(ctx context.Context, req *mcp.CallToolRequest, args map[string]any) (*mcp.CallToolResult, map[string]any, error) {
		result, err := g.handleToolCall(ctx, req.Params.Name, args)
		return result, nil, err
	})
}

// handleToolCall applies the fast-path, logs the decision, and routes the call
// to either the local filesystem server or Keep.
func (g *Gate) handleToolCall(ctx context.Context, toolName string, args map[string]any) (*mcp.CallToolResult, error) {
	requestID := uuid.New().String()

	fpResult, err := g.FastPath(ctx, toolName, args)
	if err != nil {
		return nil, err
	}

	paths := extractPaths(args)
	path := ""
	if len(paths) > 0 {
		path = paths[0]
	}

	switch fpResult {
	case FastPathAllow:
		slog.Info("fast-path allow", "tool", toolName, "path", path, "request_id", requestID)

		// Queue decision log entry
		select {
		case g.logChan <- DecisionLogEntry{
			Timestamp: time.Now().UTC(),
			SessionID: g.sessionID,
			RequestID: requestID,
			UserID:    g.identity.Get(ctx).UserID,
			ToolName:  toolName,
			Decision:  "allow",
			Reason:    "sandbox",
			Source:    "gate-fastpath",
			Arguments: args,
		}:
		default:
			// Channel full, skip logging (don't block)
		}

		if g.localFS == nil {
			return nil, fmt.Errorf("local filesystem server not configured")
		}
		return g.localFS.CallTool(ctx, &mcp.CallToolParams{
			Name:      toolName,
			Arguments: args,
		})

	case FastPathDeny:
		slog.Info("fast-path deny", "tool", toolName, "path", path, "request_id", requestID)

		// Queue decision log entry
		select {
		case g.logChan <- DecisionLogEntry{
			Timestamp: time.Now().UTC(),
			SessionID: g.sessionID,
			RequestID: requestID,
			UserID:    g.identity.Get(ctx).UserID,
			ToolName:  toolName,
			Decision:  "deny",
			Reason:    "protected path",
			Source:    "gate-fastpath",
			Arguments: args,
		}:
		default:
			// Channel full, skip logging (don't block)
		}

		return nil, shared.ErrDenied
	}

	// Forward to Keep.
	serverName, ok := g.toolServerMap[toolName]
	if !ok {
		slog.Warn("no server mapping for tool, routing may fail", "tool", toolName)
		serverName = "unknown"
	}
	currentIdentity := g.identity.Get(ctx)
	enriched := shared.EnrichedMCPRequest{
		ServerName:       serverName,
		ToolName:         toolName,
		Arguments:        args,
		UserIdentity:     currentIdentity,
		EscalationTokens: g.store.All(),
		SessionID:        g.sessionID,
		RequestID:        requestID,
	}
	return g.forwarder.CallTool(ctx, enriched)
}

// logWorker batches decision log entries and sends them to Keep periodically.
func (g *Gate) logWorker() {
	defer g.logWg.Done()

	flushInterval := 30 * time.Second // default
	if g.cfg.DecisionLogs.FlushInterval > 0 {
		flushInterval = time.Duration(g.cfg.DecisionLogs.FlushInterval) * time.Second
	}

	maxBatchSize := 100 // default
	if g.cfg.DecisionLogs.MaxBatchSize > 0 {
		maxBatchSize = g.cfg.DecisionLogs.MaxBatchSize
	}

	ticker := time.NewTicker(flushInterval)
	defer ticker.Stop()

	var batch []DecisionLogEntry

	for {
		select {
		case <-g.logDone:
			// Drain remaining entries and flush
			for {
				select {
				case entry := <-g.logChan:
					batch = append(batch, entry)
				default:
					// Channel is empty
					if len(batch) > 0 {
						g.flushLogs(batch)
					}
					return
				}
			}

		case entry := <-g.logChan:
			batch = append(batch, entry)

			// Flush if batch reaches max size
			if len(batch) >= maxBatchSize {
				g.flushLogs(batch)
				batch = batch[:0]
			}

		case <-ticker.C:
			// Periodic flush
			if len(batch) > 0 {
				g.flushLogs(batch)
				batch = batch[:0]
			}
		}
	}
}

// flushLogs sends a batch of decision log entries to Keep.
func (g *Gate) flushLogs(entries []DecisionLogEntry) {
	if len(entries) == 0 {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := g.forwarder.SendLogs(ctx, entries); err != nil {
		slog.Warn("failed to send decision logs to keep", "error", err, "count", len(entries))
		// Don't retry - just log the error
	} else {
		slog.Debug("sent decision logs to keep", "count", len(entries))
	}
}
