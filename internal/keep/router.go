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
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"sync"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/paclabsnet/PortcullisMCP/internal/shared"
)

// MCPBackend routes tool calls to a registered MCP backend server.
type MCPBackend interface {
	CallTool(ctx context.Context, serverName, toolName string, args map[string]any) (*mcp.CallToolResult, error)
	ListTools(ctx context.Context, serverName string) ([]*mcp.Tool, error)
}

// Router maintains MCP client sessions to all registered backend servers.
type Router struct {
	mu         sync.Mutex
	backends   map[string]*backendConn
	cacheMu    sync.RWMutex
	toolCache  []shared.AnnotatedTool
}

type backendConn struct {
	cfg         BackendConfig
	client      *mcp.Client
	session     *mcp.ClientSession
	aliasToReal map[string]string // alias → real backend tool name; nil if no aliases
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
// toolName is the alias as seen by the agent and PDP; it is un-aliased to the
// real backend tool name before dispatch so the PDP always evaluates the alias.
func (r *Router) CallTool(ctx context.Context, serverName, toolName string, args map[string]any) (*mcp.CallToolResult, error) {
	ctx, span := otel.Tracer("portcullis-keep").Start(ctx, "keep.backend.call_tool")
	defer span.End()
	span.SetAttributes(
		attribute.String("backend.name", serverName),
		attribute.String("tool.name", toolName),
	)

	backendToolName := r.resolveToolName(serverName, toolName)

	session, err := r.sessionFor(ctx, serverName)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	result, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name:      backendToolName,
		Arguments: args,
	})
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
	}
	return result, err
}

// resolveToolName returns the real backend tool name for the given alias, or
// the original name unchanged if no alias mapping exists for it.
func (r *Router) resolveToolName(serverName, toolName string) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if conn, ok := r.backends[serverName]; ok && conn.aliasToReal != nil {
		if real, ok := conn.aliasToReal[toolName]; ok {
			return real
		}
	}
	return toolName
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

// ListAllTools returns the cached aggregated tool list from all registered backends.
// The cache is populated at startup and refreshed via Reload.
func (r *Router) ListAllTools(ctx context.Context) ([]shared.AnnotatedTool, error) {
	r.cacheMu.RLock()
	defer r.cacheMu.RUnlock()
	return r.toolCache, nil
}

// Reload reconciles the backend map against the new config, re-surveys all
// backends via MCP ListTools, and updates the tool cache. Backends removed from
// config have their sessions closed. New backends are registered. Existing
// sessions are reused (connection params changes require restart — known gap).
// ToolMap changes take effect immediately on reload. A backend that fails to
// list tools is logged and skipped so one broken backend does not prevent the
// rest from being served. Duplicate aliases across backends are a hard error.
func (r *Router) Reload(ctx context.Context, backends map[string]BackendConfig) error {
	r.mu.Lock()

	// Close and remove backends no longer in config.
	for name, conn := range r.backends {
		if _, exists := backends[name]; !exists {
			if conn.session != nil {
				conn.session.Close()
			}
			delete(r.backends, name)
		}
	}

	// Register new backends and update configs for existing ones (so ToolMap
	// and other non-connection settings take effect without a restart).
	for name, cfg := range backends {
		if conn, exists := r.backends[name]; exists {
			conn.cfg = cfg
		} else {
			r.backends[name] = &backendConn{cfg: cfg}
		}
	}

	// Validate alias uniqueness across all backends, then build aliasToReal
	// maps. aliasToReal is the inverse of ToolMap (alias → real backend name).
	seenAliases := make(map[string]string) // alias → backend that claimed it
	for name, conn := range r.backends {
		for realName, alias := range conn.cfg.ToolMap {
			if claimedBy, dup := seenAliases[alias]; dup {
				r.mu.Unlock()
				return fmt.Errorf("tool alias %q is claimed by both backend %q and %q — aliases must be unique across all backends (real names: %q)", alias, claimedBy, name, realName)
			}
			seenAliases[alias] = name
		}
	}
	for _, conn := range r.backends {
		if len(conn.cfg.ToolMap) == 0 {
			conn.aliasToReal = nil
		} else {
			m := make(map[string]string, len(conn.cfg.ToolMap))
			for realName, alias := range conn.cfg.ToolMap {
				m[alias] = realName
			}
			conn.aliasToReal = m
		}
	}

	// Snapshot names and ToolMaps before releasing the lock so the survey loop
	// below does not need to re-acquire mu.
	type backendMeta struct{ toolMap map[string]string }
	meta := make(map[string]backendMeta, len(r.backends))
	names := make([]string, 0, len(r.backends))
	for name, conn := range r.backends {
		meta[name] = backendMeta{toolMap: conn.cfg.ToolMap}
		names = append(names, name)
	}
	r.mu.Unlock()

	// Survey all backends (without holding mu to avoid deadlock with sessionFor).
	var surveys []backendSurvey
	for _, name := range names {
		tools, err := r.ListTools(ctx, name)
		if err != nil {
			slog.Warn("reload: list tools failed for backend", "backend", name, "error", err)
			continue
		}
		surveys = append(surveys, backendSurvey{name: name, toolMap: meta[name].toolMap, tools: tools})
	}

	all, err := buildToolCache(surveys)
	if err != nil {
		return err
	}

	r.cacheMu.Lock()
	r.toolCache = all
	r.cacheMu.Unlock()

	slog.Info("tool cache refreshed", "tool_count", len(all), "backend_count", len(names))
	return nil
}

// backendSurvey holds the result of a single backend's ListTools call together
// with its alias map, ready to be merged into the global tool cache.
type backendSurvey struct {
	name    string
	toolMap map[string]string // real name → alias (from BackendConfig.ToolMap)
	tools   []*mcp.Tool
}

// buildToolCache merges surveyed tools from all backends into a single list,
// applying any alias mappings and returning an error if any effective name
// (alias or real) appears more than once across all backends.
// This catches alias-vs-alias, alias-vs-unaliased, and unaliased-vs-unaliased
// collisions that would otherwise silently shadow tools in the agent's view.
func buildToolCache(surveys []backendSurvey) ([]shared.AnnotatedTool, error) {
	type effectiveEntry struct {
		backendName string
		realName    string // non-empty only when the effective name is an alias
	}
	seenEffective := make(map[string]effectiveEntry)
	var all []shared.AnnotatedTool

	for _, s := range surveys {
		for _, t := range s.tools {
			effectiveName := t.Name
			var realName string
			if alias, ok := s.toolMap[t.Name]; ok {
				realName = t.Name
				effectiveName = alias
			}
			if prior, dup := seenEffective[effectiveName]; dup {
				return nil, fmt.Errorf(
					"effective tool name %q collides: %s and %s — use tool_map to give one a unique alias",
					effectiveName,
					describeToolEntry(prior.backendName, effectiveName, prior.realName),
					describeToolEntry(s.name, effectiveName, realName),
				)
			}
			seenEffective[effectiveName] = effectiveEntry{backendName: s.name, realName: realName}

			entry := shared.AnnotatedTool{ServerName: s.name, Tool: t}
			if realName != "" {
				// Shallow-copy the tool so we do not mutate the SDK-owned value.
				toolCopy := *t
				toolCopy.Name = effectiveName
				entry.Tool = &toolCopy
			}
			all = append(all, entry)
		}
	}
	return all, nil
}

// describeToolEntry returns a human-readable description of how a backend
// exposes a tool, for use in collision error messages.
func describeToolEntry(backendName, effectiveName, realName string) string {
	if realName != "" {
		return fmt.Sprintf("backend %q exposes it as an alias for %q", backendName, realName)
	}
	return fmt.Sprintf("backend %q exposes %q as its real name", backendName, effectiveName)
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
		if len(cfg.Env) > 0 {
			// Start from the parent environment so PATH and other essentials
			// are inherited, then overlay the per-backend overrides.
			cmd.Env = os.Environ()
			for k, v := range cfg.Env {
				cmd.Env = append(cmd.Env, k+"="+v)
			}
		}
		return &mcp.CommandTransport{Command: cmd}, nil
	case "http":
		if cfg.URL == "" {
			return nil, fmt.Errorf("http backend requires a URL")
		}
		if err := checkBackendURL(cfg.URL, cfg.AllowPrivateAddresses); err != nil {
			return nil, fmt.Errorf("http backend URL rejected: %w", err)
		}
		return &mcp.StreamableClientTransport{
			Endpoint:   cfg.URL,
			HTTPClient: noRedirectHTTPClient(),
		}, nil
	default:
		return nil, fmt.Errorf("unsupported backend type %q", cfg.Type)
	}
}

// noRedirectHTTPClient returns an http.Client that refuses to follow any
// redirect. This prevents SSRF attacks where a legitimate MCP backend
// redirects Keep to an internal service or metadata endpoint.
func noRedirectHTTPClient() *http.Client {
	return &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return fmt.Errorf("redirects are not permitted for MCP backend calls (attempted redirect to %s)", req.URL)
		},
	}
}

// privateRanges lists the CIDR blocks that must not be reachable via HTTP
// backend URLs: RFC 1918 private ranges, loopback, and link-local.
var privateRanges = func() []*net.IPNet {
	var ranges []*net.IPNet
	for _, cidr := range []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"::1/128",
		"169.254.0.0/16", // IPv4 link-local
		"fe80::/10",      // IPv6 link-local
		"fc00::/7",       // IPv6 unique-local
	} {
		_, network, _ := net.ParseCIDR(cidr)
		ranges = append(ranges, network)
	}
	return ranges
}()

// checkBackendURL validates that a backend URL is an absolute HTTP/HTTPS URL.
// Unless allowPrivate is true, it also rejects hosts that resolve to RFC 1918,
// loopback, or link-local addresses. This is a config-load-time check; the
// no-redirect client handles runtime SSRF regardless of this setting.
func checkBackendURL(rawURL string, allowPrivate bool) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("scheme %q not allowed; use http or https", u.Scheme)
	}
	if allowPrivate {
		return nil
	}
	hostname := u.Hostname()
	ips, err := net.LookupHost(hostname)
	if err != nil {
		// DNS failure at config time is non-fatal: the host may not be
		// resolvable in the build/test environment. Log and allow.
		slog.Warn("backend URL: could not resolve host at config time",
			"host", hostname, "error", err)
		return nil
	}
	for _, ipStr := range ips {
		ip := net.ParseIP(ipStr)
		if ip == nil {
			continue
		}
		for _, private := range privateRanges {
			if private.Contains(ip) {
				return fmt.Errorf("host %q resolves to private/loopback address %s — "+
					"set allow_private_addresses: true if this backend is intentionally on an internal network",
					hostname, ipStr)
			}
		}
	}
	return nil
}
