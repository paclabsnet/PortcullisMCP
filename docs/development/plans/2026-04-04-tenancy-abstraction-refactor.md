# Gate Tenancy Abstraction Refactor Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Refactor `portcullis-gate` to use a `TenancyProvider` interface, consolidating environmental behaviors and removing scattered `if cfg.Tenancy == "multi"` checks.

**Architecture:** Introduce `TenancyProvider` and `Capabilities` in `internal/gate/tenancy.go`. Create `SingleTenantProvider` and `MultiTenantProvider` implementations. Inject the provider into `Gate` and `MCPHTTPHandler` to delegate identity extraction, capability checks, and policy error mapping.

**Tech Stack:** Go, MCP Go SDK

---

### Task 1: Define Tenancy Interface and Capabilities

**Files:**
- Create: `internal/gate/tenancy.go`

- [ ] **Step 1: Define the interface and capability struct**

```go
package gate

import (
	"context"
	"net/http"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type TenancyProvider interface {
	// Authenticate extracts the user's identity and maps it to a session.
	Authenticate(r *http.Request) (rawToken, sessionID string, err error)

	// Capabilities returns the feature flags allowed for this tenancy mode.
	Capabilities() Capabilities

	// MapPolicyError converts internal policy results into MCP Tool results.
	// It returns (result, handled). If handled=true, the caller should return the result immediately.
	MapPolicyError(ctx context.Context, err error, tool, traceID string, cfg *Config) (*mcp.CallToolResult, bool)
}

type Capabilities struct {
	AllowLocalFS      bool
	AllowManagementUI bool
	AllowGuardPeer    bool
	AllowHumanInLoop  bool
	AllowNativeTools  bool
}
```

- [ ] **Step 2: Commit**

```bash
git add internal/gate/tenancy.go
git commit -m "refactor: define TenancyProvider interface and Capabilities"
```

---

### Task 2: Implement SingleTenantProvider

**Files:**
- Create: `internal/gate/single_tenant.go`

- [ ] **Step 1: Implement SingleTenantProvider**

```go
package gate

import (
	"context"
	"errors"
	"net/http"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/paclabsnet/PortcullisMCP/internal/shared"
)

type SingleTenantProvider struct {
	id          IdentitySource
	tokenHeader string
}

func NewSingleTenantProvider(id IdentitySource, tokenHeader string) *SingleTenantProvider {
	return &SingleTenantProvider{id: id, tokenHeader: tokenHeader}
}

func (p *SingleTenantProvider) Authenticate(r *http.Request) (string, string, error) {
	rawToken := ""
	if p.tokenHeader != "" {
		rawToken = r.Header.Get(p.tokenHeader)
	}
	if rawToken == "" && p.id != nil {
		rawToken = p.id.Get(r.Context()).RawToken
	}
	sessionID := r.Header.Get("Mcp-Session-Id")
	return rawToken, sessionID, nil
}

func (p *SingleTenantProvider) Capabilities() Capabilities {
	return Capabilities{
		AllowLocalFS:      true,
		AllowManagementUI: true,
		AllowGuardPeer:    true,
		AllowHumanInLoop:  true,
		AllowNativeTools:  true,
	}
}

func (p *SingleTenantProvider) MapPolicyError(ctx context.Context, err error, tool, traceID string, cfg *Config) (*mcp.CallToolResult, bool) {
	// Single tenant mode uses standard buildDenyMessage/buildEscalationMessage logic in server.go for now,
	// returning handled=false to fall through to that logic.
	return nil, false
}
```

- [ ] **Step 2: Commit**

```bash
git add internal/gate/single_tenant.go
git commit -m "feat: implement SingleTenantProvider"
```

---

### Task 3: Implement MultiTenantProvider

**Files:**
- Create: `internal/gate/multi_tenant_provider.go`

- [ ] **Step 1: Implement MultiTenantProvider**

```go
package gate

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/paclabsnet/PortcullisMCP/internal/shared"
)

type MultiTenantProvider struct {
	tokenHeader string
	sessions    SessionStore
	logChan     chan<- DecisionLogEntry
}

func NewMultiTenantProvider(tokenHeader string, sessions SessionStore, logChan chan<- DecisionLogEntry) *MultiTenantProvider {
	return &MultiTenantProvider{
		tokenHeader: tokenHeader,
		sessions:    sessions,
		logChan:     logChan,
	}
}

func (p *MultiTenantProvider) Authenticate(r *http.Request) (string, string, error) {
	rawToken := ""
	if p.tokenHeader != "" {
		rawToken = r.Header.Get(p.tokenHeader)
	}
	if rawToken == "" {
		return "", "", nil // Middleware will handle 401
	}

	sessionID := r.Header.Get("Mcp-Session-Id")
	ctx := r.Context()

	if p.sessions != nil {
		if sessionID != "" {
			storedState, _, err := p.sessions.GetSession(ctx, sessionID)
			switch {
			case errors.Is(err, ErrSessionNotFound):
				sessionID = ""
			case err != nil:
				return "", "", err
			default:
				if !bytes.Equal(storedState, credentialFingerprint(rawToken)) {
					return "", "", errors.New("forbidden: session fingerprint mismatch")
				}
			}
		}

		if sessionID == "" {
			sessionID = uuid.NewString()
			fp := credentialFingerprint(rawToken)
			if err := p.sessions.SaveSession(ctx, sessionID, "", fp); err != nil {
				return "", "", err
			}
		}
	}

	return rawToken, sessionID, nil
}

func (p *MultiTenantProvider) Capabilities() Capabilities {
	return Capabilities{
		AllowLocalFS:      false,
		AllowManagementUI: false,
		AllowGuardPeer:    false,
		AllowHumanInLoop:  false,
		AllowNativeTools:  false,
	}
}

func (p *MultiTenantProvider) MapPolicyError(ctx context.Context, err error, tool, traceID string, cfg *Config) (*mcp.CallToolResult, bool) {
	var escalationErr *shared.EscalationPendingError
	var denyErr *shared.DenyError

	if errors.As(err, &escalationErr) || errors.As(err, &denyErr) || errors.Is(err, shared.ErrDenied) {
		sid, _ := SessionIDFromContext(ctx)
		select {
		case p.logChan <- DecisionLogEntry{
			Timestamp: time.Now().UTC(),
			SessionID: sid,
			TraceID:   traceID,
			ToolName:  tool,
			Decision:  "deny",
			Reason:    "multi-tenant: escalation intercepted",
			Source:    "gate-multitenant",
		}:
		default:
		}

		marker := cfg.Responsibility.Escalation.NoEscalationMarker
		if marker == "" {
			marker = "Access denied."
		}
		return &mcp.CallToolResult{
			IsError: true,
			Content: []mcp.Content{&mcp.TextContent{Text: marker}},
		}, true
	}

	return nil, false
}
```

- [ ] **Step 2: Commit**

```bash
git add internal/gate/multi_tenant_provider.go
git commit -m "feat: implement MultiTenantProvider"
```

---

### Task 4: Integrate Provider into Gate Struct

**Files:**
- Modify: `internal/gate/server.go`

- [ ] **Step 1: Update Gate struct and New initialization**

Add `provider TenancyProvider` to `Gate` struct.
In `New`, initialize the provider based on `cfg.Tenancy`.

```go
// ... in Gate struct
	provider      TenancyProvider
// ...

// ... in New
	var provider TenancyProvider
	mcpEp := cfg.Server.Endpoints[MCPEndpoint]
	if cfg.Tenancy == "multi" {
		provider = NewMultiTenantProvider(mcpEp.Auth.Credentials.Header, sessionStore, nil) // logChan set later
	} else {
		provider = NewSingleTenantProvider(identityCache, mcpEp.Auth.Credentials.Header)
	}
// ...
	g := &Gate{
		// ...
		provider:      provider,
	}

	// Update MultiTenantProvider with logChan
	if mtp, ok := provider.(*MultiTenantProvider); ok {
		mtp.logChan = g.logChan
	}
```

- [ ] **Step 2: Update capability checks in New and Run**

Replace `cfg.Tenancy != "multi"` with `g.provider.Capabilities().AllowLocalFS`, etc.

- [ ] **Step 3: Update maybeStorePendingEscalation and policyErrToResult**

```go
func (g *Gate) maybeStorePendingEscalation(ctx context.Context, serverName, toolName string, err error) error {
	if !g.provider.Capabilities().AllowHumanInLoop {
		return nil
	}
    // ...
}

func (g *Gate) policyErrToResult(ctx context.Context, err error, toolName, traceID string) (*mcp.CallToolResult, error) {
	if result, handled := g.provider.MapPolicyError(ctx, err, toolName, traceID, &g.cfg); handled {
		return result, nil
	}
    // ... existing single-tenant logic
}
```

- [ ] **Step 4: Commit**

```bash
git add internal/gate/server.go
git commit -m "refactor: integrate TenancyProvider into Gate"
```

---

### Task 5: Refactor MCPHTTPHandler to use Provider

**Files:**
- Modify: `internal/gate/mcp_http.go`

- [ ] **Step 1: Update MCPHTTPHandler struct and ServeHTTP**

Remove tenancy-specific fields from `MCPHTTPHandler` and use `provider.Authenticate`.

```go
type MCPHTTPHandler struct {
	provider    TenancyProvider
	authType    string
	sdkHandler  http.Handler
}

func NewMCPHTTPHandler(
	srv *mcp.Server,
	sdkOpts *mcp.StreamableHTTPOptions,
	cfg Config,
	provider TenancyProvider,
) *MCPHTTPHandler {
    // ...
	return &MCPHTTPHandler{
		provider:    provider,
		authType:    mcpEp.Auth.Type,
		sdkHandler:  sdkHandler,
	}
}

func (h *MCPHTTPHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
    // ... health checks ...

	rawToken, sessionID, err := h.provider.Authenticate(r)
	if err != nil {
		if strings.Contains(err.Error(), "forbidden") {
			http.Error(w, "Forbidden", http.StatusForbidden)
		} else {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		}
		return
	}

	if h.authType != "" && h.authType != "none" && rawToken == "" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	ctx := r.Context()
	if sessionID != "" {
		ctx = withSessionID(ctx, sessionID)
	}
	if rawToken != "" {
		ctx = context.WithValue(ctx, identityKey, shared.UserIdentity{RawToken: rawToken})
	}
	r = r.WithContext(ctx)

	h.sdkHandler.ServeHTTP(w, r)
}
```

- [ ] **Step 2: Update Gate.Run to pass the provider**

```go
httpHandler := NewMCPHTTPHandler(g.server, sdkOpts, g.cfg, g.provider)
```

- [ ] **Step 3: Commit**

```bash
git add internal/gate/mcp_http.go internal/gate/server.go
git commit -m "refactor: delegate authentication to TenancyProvider in MCPHTTPHandler"
```

---

### Task 6: Verification and Testing

**Files:**
- Modify: `internal/gate/multi_tenant_test.go`
- Modify: `internal/gate/mcp_http_test.go`

- [ ] **Step 1: Run all gate tests**

Run: `go test -v ./internal/gate/...`
Expected: PASS

- [ ] **Step 2: Add abstraction-specific tests if needed**

- [ ] **Step 3: Commit**

```bash
git commit -m "test: verify tenancy abstraction refactor"
```
