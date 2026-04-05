# Multi-tenant Gate Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Shift `portcullis-gate` from a local developer utility to a robust, identity-aware server capable of supporting multiple simultaneous users (Customers) via a central Agent.

**Architecture:** Introduce `tenancy: multi` mode. Replace the legacy `mcp.StdioTransport{}` with a stateless MCP-over-HTTP transport mapping sessions to Redis. In multi-tenant mode, local tools and "human-in-the-loop" escalations are forcibly disabled, and escalation decisions emit SIEM audit logs instead.

**Tech Stack:** Go, MCP Go SDK (`github.com/modelcontextprotocol/go-sdk/mcp`), Redis (`github.com/redis/go-redis/v9`), Miniredis (`github.com/alicebob/miniredis/v2`)

---

### Task 0.1: Context Helpers & SessionStore Interface

**Goal:** Define the foundational context keys and stateful session storage interface.

**Files:**
- Modify: `internal/gate/server.go`
- Create: `internal/gate/session_store.go`

- [ ] **Step 1: Define Context Keys**
Add context key types and constants to `internal/gate/server.go`:
```go
type gateCtxKey string
const (
    sessionIDKey gateCtxKey = "sessionID"
    userIDKey    gateCtxKey = "userID"
    identityKey  gateCtxKey = "identity" 
)
```

- [ ] **Step 2: Define SessionStore Interface**
Create `internal/gate/session_store.go` with the interface and sentinel:
```go
package gate

import (
	"context"
	"errors"
)

var ErrSessionNotFound = errors.New("session not found")

type SessionStore interface {
	SaveSession(ctx context.Context, sessionID, userID string, state []byte) error
	GetSession(ctx context.Context, sessionID string) (state []byte, userID string, err error)
	DeleteSession(ctx context.Context, sessionID string) error
}
```

- [ ] **Step 3: Commit**
```bash
git add internal/gate/server.go internal/gate/session_store.go
git commit -m "refactor: define context keys and session store interface"
```

---

### Task 0.2: Interface Injection and Gate Refactor

**Goal:** Abstract identity and token storage, and inject interfaces into the `Gate` struct.

**Files:**
- Modify: `internal/gate/identity.go`
- Modify: `internal/gate/tokenstore.go`
- Modify: `internal/gate/server.go`

- [ ] **Step 1: Abstract Interfaces**
Define `IdentitySource` in `internal/gate/identity.go`:
```go
type IdentitySource interface {
    Get(ctx context.Context) shared.UserIdentity
    SetToken(raw string) error
    Clear()
}
```
In `internal/gate/tokenstore.go`, define:
- `EscalationTokenStore`: For managing short-lived escalation JWTs.
- `PendingEscalationStore`: For managing in-flight escalation requests (replaces the `pendingEscalations` map).

Ensure existing implementations fulfill them.

- [ ] **Step 2: Update Gate Struct**
```go
type Gate struct {
    cfg           Config
    sessions      SessionStore             // Handles session state
    escalations   EscalationTokenStore     // Handles escalation JWTs
    pending       PendingEscalationStore   // Handles in-flight requests
    identity      IdentitySource           // Handles user info resolution
    // ...
}
```
Update `New` to initialize these. 
**Durability Rule:** For `tenancy: single`, the `EscalationTokenStore` MUST remain file-backed (e.g., using the existing `tokens.json` implementation) to ensure approvals survive server restarts.

- [ ] **Step 3: Verify Build**
Run: `go build ./internal/gate/...`
Expected: Compilation success.

- [ ] **Step 4: Commit**
```bash
git add internal/gate/identity.go internal/gate/tokenstore.go internal/gate/server.go
git commit -m "refactor: abstract interfaces and inject into Gate struct"
```

---

### Task 0.3: Context-Aware Method Signatures

**Goal:** Update core `Gate` methods to pull state from `context.Context` instead of struct fields.

**Files:**
- Modify: `internal/gate/server.go`
- Modify: `internal/gate/oidclogin.go`

- [ ] **Step 1: Refactor core methods**
Update `handleToolCall`, `FastPath`, `maybeStorePendingEscalation`, `collectEscalationTokens`, and `policyErrToResult` to accept and use `context.Context` for session and identity data.
**Global State Rule (Single-Tenant):** 
In `tenancy: single` mode, all interactions with `PendingEscalationStore` and `EscalationTokenStore` MUST NOT be session-prefixed. This ensures that pending requests and final approvals are global to the user across all desktop agents for the best UX. (In multi-tenant mode, these stores are bypassed entirely).

- [ ] **Step 2: Update OIDC Login**
Update the OIDC callback handler in `internal/gate/oidclogin.go` to save the final user token into the `IdentitySource` (implemented by `IdentityCache`) upon successful authentication.

- [ ] **Step 3: Run existing tests**
Run: `go test -v ./internal/gate/...`
Expected: PASS (single-tenant mode regression check).

- [ ] **Step 4: Commit**
```bash
git add internal/gate/server.go internal/gate/oidclogin.go
git commit -m "refactor: make core Gate methods context-aware and wire IdentitySource"
```

---

### Task 1.1: Responsibility Config Struct Restructuring

**Goal:** Move `workspace` and `forbidden` under the new `tools.portcullis-localfs` hierarchy and add missing fields.

**Files:**
- Modify: `internal/gate/config.go`
- Modify: `internal/gate/config_test.go`
- Modify: `internal/gate/server.go`
- Modify: `internal/gate/server_escalation_test.go`
- Modify: `internal/gate/server_secrets_test.go`

- [ ] **Step 1: Update Config Structures**
In `internal/gate/config.go`, add `Tenancy` to the main `Config` struct and update the nested structures:
```go
type Config struct {
    Tenancy        string               `yaml:"tenancy"` // "single" or "multi"
    Server         ServerConfig         `yaml:"server"`
    Responsibility ResponsibilityConfig `yaml:"responsibility"`
    // ... rest of fields
}

type ResponsibilityConfig struct {
	Tools            ToolsConfig            `yaml:"tools"`
	AgentInteraction AgentInteractionConfig `yaml:"agent_interaction"`
	Escalation       EscalationConfig       `yaml:"escalation"`
	DecisionLogs     DecisionLogBatchConfig `yaml:"decision_logs"`
}

type ToolsConfig struct {
	LocalFS LocalFSConfig `yaml:"portcullis-localfs"`
}

type LocalFSConfig struct {
	Enabled   bool            `yaml:"enabled"`
	Workspace SandboxConfig   `yaml:"workspace"`
	Forbidden ForbiddenConfig `yaml:"forbidden"`
}

type EscalationConfig struct {
    Enabled            bool   `yaml:"enabled"`
	Strategy           string `yaml:"strategy"`
	PollInterval       int    `yaml:"poll_interval"`
	TokenStore         string `yaml:"token_store"`
	NoEscalationMarker string `yaml:"no_escalation_marker"`
}
```

- [ ] **Step 2: Update References & Allowlist**
Update `Responsibility.Workspace`, `Responsibility.Forbidden`, and `Responsibility.Escalation` to their new nested paths across the codebase.
Add `"server.endpoints.mcp.auth.credentials.bearer_token"` to `SecretAllowlist`.

- [ ] **Step 3: Run Tests**
Run: `go test -v ./internal/gate/...`

- [ ] **Step 4: Commit**
```bash
git add internal/gate/config.go internal/gate/config_test.go internal/gate/server.go internal/gate/server_escalation_test.go internal/gate/server_secrets_test.go
git commit -m "feat: restructure responsibility configuration hierarchy"
```

---

### Task 1.2: Multi-tenant Configuration Validation

**Goal:** Configure Storage (using existing `StorageConfig`) and enforce all `tenancy: multi` isolation rules.

**Files:**
- Modify: `internal/shared/config/unified.go`
- Modify: `internal/gate/config.go`
- Modify: `internal/gate/config_test.go`

- [ ] **Step 1: Update Server & Auth Structs (Deltas)**
In `internal/shared/config/unified.go`, add `SessionTTL` to `ServerConfig` and `Header` to `AuthCredentials`. 
**Note:** `StorageConfig` and `OperationsConfig.Storage` are already defined in `unified.go` and will be used for session persistence.
```go
type ServerConfig struct {
	Endpoints  map[string]EndpointConfig `yaml:"endpoints"`
	SessionTTL int                       `yaml:"session_ttl"` // Added for session management
}

type AuthCredentials struct {
	BearerToken string `yaml:"bearer_token"`
	Cert        string `yaml:"cert"`
	Key         string `yaml:"key"`
	ServerCA    string `yaml:"server_ca"`
	Header      string `yaml:"header"` // Added for token extraction
}
```

- [ ] **Step 2: Implement Validation Logic**
Update `Validate` in `internal/gate/config.go` to enforce rules based on the `Tenancy` / `Transport` matrix:

**If `Tenancy == "multi"`:**
1. `Server.Endpoints["mcp"].Listen` must be configured (HTTP transport is required).
2. `Responsibility.Tools.LocalFS.Enabled` must be false (isolation).
3. `Responsibility.Escalation.Enabled` must be false (SIEM mode only).
4. `Server.Endpoints["management_ui"]` must not exist.
5. `Peers.Guard` must not be configured (no Endpoint / Endpoints).
6. `Identity.Strategy` must not be "oidc-login" (Central Agent uses Header tokens).
7. `Server.SessionTTL` must be > 0.
8. If Storage backend is "redis", verify `Storage.Config["addr"]` exists.

**If `Tenancy == "single"` (even if HTTP transport is used):**
1. OIDC-login, Escalation, LocalFS, and Management UI are ALL permitted and should function as expected.
2. If `responsibility.escalation.enabled == true`, `peers.guard` must exist.

- [ ] **Step 3: Verify with Tests**
Add specific test cases in `internal/gate/config_test.go` for each validation rule and run:
`go test -v ./internal/gate -run TestConfig_TenancyValidation`

- [ ] **Step 4: Commit**
```bash
git add internal/shared/config/unified.go internal/gate/config.go internal/gate/config_test.go
git commit -m "feat: enforce multi-tenancy isolation rules and define StorageConfig"
```

---

### Task 2.1: Memory Session Store

**Goal:** Provide a thread-safe memory implementation of `SessionStore`.

**Files:**
- Create: `internal/gate/memory_session_store.go`
- Create: `internal/gate/memory_session_store_test.go`

- [ ] **Step 1: Implement MemorySessionStore**
Create a struct with a `sync.RWMutex` protecting a map of sessions.

- [ ] **Step 2: Write and run tests**
Test `SaveSession` and `GetSession` concurrently.
Run: `go test -v ./internal/gate -run TestMemorySessionStore`

- [ ] **Step 3: Commit**
```bash
git add internal/gate/memory_session_store.go internal/gate/memory_session_store_test.go
git commit -m "feat: implement memory session store"
```

---

### Task 2.2: Redis Session Store

**Goal:** Provide a Redis-backed implementation of `SessionStore` with TTL.

**Files:**
- Create: `internal/gate/redis_session_store.go`
- Create: `internal/gate/redis_session_store_test.go`

- [ ] **Step 1: Implement RedisSessionStore**
Use `github.com/redis/go-redis/v9`. Set expiry using the configured TTL during `SaveSession`.

- [ ] **Step 2: Write and run tests using miniredis**
Verify save, fetch, and correct TTL application in Redis.
Run: `go test -v ./internal/gate -run TestRedisSessionStore`

- [ ] **Step 3: Commit**
```bash
git add internal/gate/redis_session_store.go internal/gate/redis_session_store_test.go
git commit -m "feat: implement redis session store with TTL"
```

---

### Task 3.0: SDK API Verification

**Goal:** Verify `mcp.EventStore` and `mcp.NewStreamableHTTPHandler` signatures in `go-sdk v1.4.0`.

- [ ] **Step 1: Verify SDK Signatures**
Confirm `github.com/modelcontextprotocol/go-sdk/mcp` includes `EventStore` and check the correct constructor for the HTTP handler (e.g., `NewStreamableHTTPHandler` or `NewHTTPHandler` with stream options) to ensure Task 3.1 and 3.3 implementations are grounded in the actual library API.

---

### Task 3.1: Redis EventStore for MCP Resumability

**Goal:** Implement `mcp.EventStore` using Redis to support SSE resumability.

**Files:**
- Modify: `internal/gate/redis_session_store.go`
- Modify: `internal/gate/redis_session_store_test.go`

- [ ] **Step 1: Implement mcp.EventStore**
Implement `Append(ctx, sessionID, event)` and `GetEvents(ctx, sessionID, lastEventID)` on the `RedisSessionStore` type, persisting to a Redis List or Stream.

- [ ] **Step 2: Write and run tests**
Run: `go test -v ./internal/gate -run TestRedisEventStore`

- [ ] **Step 3: Commit**
```bash
git add internal/gate/redis_session_store.go internal/gate/redis_session_store_test.go
git commit -m "feat: implement mcp.EventStore in redis for resumability"
```

---

### Task 3.2: Health Check Endpoints

**Goal:** Add `/healthz` and `/readyz` endpoints that bypass authentication.

**Files:**
- Create: `internal/gate/mcp_http.go`
- Create: `internal/gate/mcp_http_test.go`

- [ ] **Step 1: Implement health handlers**
In `internal/gate/mcp_http.go`:
```go
func (h *MCPHTTPHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
    if r.URL.Path == "/healthz" || r.URL.Path == "/readyz" {
        w.WriteHeader(http.StatusOK)
        w.Write([]byte("ok"))
        return
    }
    // ... middleware logic placeholder
}
```

- [ ] **Step 2: Write and run tests**
Run: `go test -v ./internal/gate -run TestMCPHTTPHealthChecks`

- [ ] **Step 3: Commit**
```bash
git add internal/gate/mcp_http.go internal/gate/mcp_http_test.go
git commit -m "feat: add health check endpoints to MCP HTTP handler"
```

---

### Task 3.3: MCP HTTP Middleware & Session Management

**Goal:** Implement the HTTP handler middleware for session extraction and identity injection.

**Definition - Credential Fingerprint:** A SHA-256 hash of the raw, base64-encoded token string provided in the configured authentication header.

**Files:**
- Modify: `internal/gate/mcp_http.go`
- Modify: `internal/gate/mcp_http_test.go`

- [ ] **Step 1: Implement Middleware Logic**
Update `ServeHTTP`:
1. Extract `Mcp-Session-Id`.
2. Extract the token from the header name configured in `endpoint.Auth.Credentials.Header` (e.g., `X-User-Token`).
3. **Single-Tenant Fallback:** If `Tenancy == "single"` and the header is missing, call `identity.Get(ctx).RawToken` (via the new `IdentitySource` interface) to retrieve the global user token.
4. If `auth.type != none` and no token is found (header or store), return 401 Unauthorized.
5. **Session Ownership Check:** 
   - If `Tenancy == "multi"` and `Mcp-Session-Id` is provided: 
     - Call `sessions.GetSession`. 
     - **Error Handling:** 
       - If `err == ErrSessionNotFound`: Proceed to Step 6 (Expired/New session).
       - If `err != nil`: Return **500 Internal Server Error** (Preserve security boundary on store failure).
     - **Fingerprint Validation:** calculate the **Credential Fingerprint** of the current request's token and compare it against the fingerprint stored in the session state.
     - **Mismatch Enforcement:** If they do not match, return **403 Forbidden**.
   - If `Tenancy == "single"`: Skip fingerprint check (all sessions belong to the local user).
6. **New Session Generation:** If `Mcp-Session-Id` was missing or `GetSession` returned `ErrSessionNotFound`, generate a new `SessionID` and store the current token's **Credential Fingerprint** in the session state.
7. Inject SessionID and the raw token into `context.Context`.
8. Delegate to `sdk.ServeHTTP`.

- [ ] **Step 2: Write and run tests**
Verify context injection, missing token denial, **single-tenant global token fallback**, **tenancy-aware ownership enforcement (fingerprint validation)**, and SSE event rehydration logic.
Run: `go test -v ./internal/gate -run TestMCPHTTPMiddleware`

- [ ] **Step 3: Commit**
```bash
git add internal/gate/mcp_http.go internal/gate/mcp_http_test.go
git commit -m "feat: implement MCP HTTP session and identity middleware"
```

---

### Task 4.1: Multi-tenant Escalation Interception

**Goal:** Intercept and block escalations in multi-tenant mode, emitting SIEM logs.

**Files:**
- Modify: `internal/gate/server.go`

- [ ] **Step 1: Implement blocking logic**
In `maybeStorePendingEscalation`:
```go
if g.cfg.Tenancy == "multi" { return nil } // Block storage in PendingEscalationStore
```
In `policyErrToResult`:
```go
if g.cfg.Tenancy == "multi" {
    sid, _ := SessionIDFromContext(ctx)
    tid := telemetry.TraceIDFromContext(ctx)
    // By design, Gate does not parse the user token; userID in SIEM logs will be empty and we supply the trace_id instead.
    // Queue DecisionLogEntry using sid and tid.
    // Return denied result with SIEM marker: g.cfg.Responsibility.Escalation.NoEscalationMarker
}
```

- [ ] **Step 2: Run existing tests**
Run: `go test -v ./internal/gate/...`
Expected: PASS (ensure no regressions in single-tenant escalation).

- [ ] **Step 3: Commit**
```bash
git add internal/gate/server.go
git commit -m "feat: intercept multi-tenant escalations for SIEM logging"
```

---

### Task 4.2: Final Gate Integration

**Goal:** Wire up the MCP HTTP transport in `Gate.Run` and ensure isolation.

**Files:**
- Modify: `internal/gate/server.go`
- Modify: `internal/gate/server_escalation_test.go`

- [ ] **Step 1: Update Gate.Run**
Switch between Stdio and HTTP transport based on whether `Server.Endpoints["mcp"]` is configured. 

**Transport/Tenancy Initialization:**
1. Initialize `RedisSessionStore` using `StorageConfig` if `Storage.Backend == "redis"`, otherwise use `MemorySessionStore`. (Note: Escalation/Pending stores are bypassed in multi-tenant mode, so they require no shared state).
2. **If HTTP transport is used AND `Tenancy == "multi"`:**
   - Do NOT register any `localFSTools` even if configured.
   - Ensure NO "native" tools are registered (`portcullis_login` and `portcullis_status` are both excluded in multi-tenant mode).
   - **Design Note:** The removal of `portcullis_status` in multi-tenant mode is deliberate. Health and readiness verification for Portcullis-Gate in this mode will be handled by external monitoring systems using the standard `/healthz` and `/readyz` endpoints.
3. **If HTTP transport is used AND `Tenancy == "single"`:**
   - Register all configured `localFSTools` and native tools as usual.
   - Management API and Guard polling should remain active.

- [ ] **Step 2: Write and run integration tests**
Verify the full multi-tenant flow from HTTP request to SIEM log emission.
Run: `go test -v ./internal/gate -run TestMultiTenantEscalation`

- [ ] **Step 3: Commit**
```bash
git add internal/gate/server.go internal/gate/server_escalation_test.go
git commit -m "feat: integrate multi-tenant HTTP transport into Gate"
```

---

### Task 5.1: Multi-tenant Boundary & Isolation Testing

**Goal:** Exhaustive verification of multi-tenant security and functional constraints.

**Files:**
- Create: `internal/gate/multi_tenant_test.go`

- [ ] **Step 1: Implement Boundary Tests**
1. **Cross-Tenant Isolation:** Verify that User A providing User B's `SessionID` (but User A's token) results in a **403 Forbidden**, never access to User B's state.
2. **Registry Strictness:** Assert that if `Tenancy == "multi"`, the `Gate` registry contains ZERO `localfs` tools, and native tools (`portcullis_login`, `portcullis_status`) are also excluded.
3. **Statelessness Audit:** Verify that after a "Deny" response in multi-tenant mode, the `PendingEscalationStore` remains empty (no leakage of "human-in-the-loop" state).
4. **Fingerprint Enforcement:** Verify that changing the token for an active `SessionID` triggers a security rejection (**403 Forbidden**).
5. **Correlation Audit:** Verify that the `trace_id` is consistently present in the emitted SIEM logs for denied requests.

- [ ] **Step 2: Run tests**
Run: `go test -v ./internal/gate -run TestMultiTenantBoundary`

- [ ] **Step 3: Commit**
```bash
git add internal/gate/multi_tenant_test.go
git commit -m "test: exhaustive multi-tenant isolation and security verification"
```