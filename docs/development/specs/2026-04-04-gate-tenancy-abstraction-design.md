# Design Spec: Gate Tenancy Abstraction

**Date:** 2026-04-04  
**Status:** Draft  
**Topic:** Refactoring multi-tenancy logic in `portcullis-gate` to use an interface-backed capability model.

## 1. Problem Statement
The current implementation of multi-tenancy in `portcullis-gate` relies on scattered `if cfg.Tenancy == "multi"` checks across several core files (`server.go`, `mcp_http.go`, `config.go`). This leads to "leaky abstractions" where the core tool-forwarding logic is tightly coupled with environment-specific behaviors (e.g., SIEM logging vs. human escalation).

## 2. Goals
- Consolidate all tenancy-specific logic into two distinct implementations of a `TenancyProvider` interface.
- Remove conditional branching based on `Tenancy` from the core `Gate` and `MCPHTTPHandler` logic.
- Improve testability by allowing tenancy behaviors to be unit-tested in isolation.
- Maintain support for both "Headless Proxy" (multi-tenant) and "Local Agent" (single-tenant) modes.

## 3. Architecture

### 3.1 The `TenancyProvider` Interface
A new interface will be defined in `internal/gate/tenancy.go` to encapsulate environmental behaviors:

```go
type TenancyProvider interface {
    // Authenticate extracts the user's identity and maps it to a session.
    // Note: This does NOT perform cryptographic token validation; identity 
    // verification is delegated to the PDP/Keep.
    Authenticate(r *http.Request) (rawToken, sessionID string, err error)

    // Capabilities returns the feature flags allowed for this tenancy mode.
    Capabilities() Capabilities

    // MapPolicyError converts internal policy results into MCP Tool results.
    // It may optionally return a DecisionLogEntry to be recorded by the server.
    MapPolicyError(ctx context.Context, err error, tool, traceID string, cfg *Config) (*mcp.CallToolResult, *DecisionLogEntry, bool)
}

type Capabilities struct {
    AllowLocalFS      bool
    AllowManagementUI bool
    AllowGuardPeer    bool
    AllowHumanInLoop  bool
    AllowNativeTools  bool
}
```

### 3.2 Implementations
Two implementations will be created, with dependencies injected via their constructors to ensure clear boundaries and testability:

1.  **`SingleTenantProvider` (`internal/gate/single_tenant.go`)**:
    - **Constructor**: `NewSingleTenantProvider(id IdentitySource, tokenHeader string, sessions SessionStore)`
    - **Authenticate**: Supports header extraction; if missing, falls back to `id.Get(ctx).RawToken`.
    - **Capabilities**: Enables LocalFS, Management UI, Guard Peer, Human-in-the-Loop escalation, and Native Tools (status/login).
    - **MapPolicyError**: Returns user-friendly messages for `EscalationPending` and `DenyError`. No log entry is returned.
2.  **`MultiTenantProvider` (`internal/gate/multi_tenant.go`)**:
    - **Constructor**: `NewMultiTenantProvider(tokenHeader string, sessions SessionStore)`
    - **Authenticate**: Enforces strict `Mcp-Session-Id` header validation and credential fingerprinting. No global identity fallback.
    - **Capabilities**: Disables all interactive/local features, including Native Tools.
    - **MapPolicyError**: Intercepts policy errors, creates a SIEM-compatible `DecisionLogEntry` (with "deny" status), and returns it along with a fixed "Access denied" marker from `cfg.Responsibility.Escalation.NoEscalationMarker`.

## 4. Integration Plan

### 4.1 `Gate` Initialization (`server.go`)
The `Gate` struct will hold a `provider TenancyProvider` field. In `New()`, the provider will be initialized based on the config. Subsystem initializations (LocalFS, GuardClient) will query `g.provider.Capabilities()` instead of checking the tenancy string.

### 4.2 `MCPHTTPHandler` (`mcp_http.go`)
The `ServeHTTP` middleware will delegate all identity and session extraction to `h.provider.Authenticate(...)`. This removes the 50-line logic block currently handling fingerprinting and fallback.

### 4.3 Policy Mapping (`server.go`)
The `policyErrToResult` method will be refactored to first call `g.provider.MapPolicyError`. If the provider handles the error (returning `true`), the result is returned immediately. This keeps SIEM-logging logic entirely within the `MultiTenantProvider`.

## 5. Testing Strategy
- **Unit Tests**: Create `internal/gate/tenancy_test.go` to verify both providers in isolation.
    - **Policy Error Boundary**: Explicitly verify that `MultiTenantProvider` intercepts `EscalationPendingError` and `DenyError`, but returns `handled=false` for infrastructure errors (e.g., `IdentityVerificationError`, transport failures).
    - **Identity Fallback**: Verify `SingleTenantProvider` falls back to global identity, while `MultiTenantProvider` returns an error if headers/sessions are missing.
- **Integration Tests**: Update `internal/gate/multi_tenant_test.go` to ensure no regressions in session isolation.
- **Verification**: Run `go test ./internal/gate/...` to confirm the refactor hasn't broken existing single-tenant or multi-tenant flows.

## 6. Self-Review Notes
- **Ambiguity**: The `MapPolicyError` signature includes `*Config` to allow access to `NoEscalationMarker`. This is acceptable as the provider is internal to the `gate` package.
- **Scope**: The refactor is limited to behavioral logic and does not change the `SessionStore` implementation, preserving the ability to use memory stores for multi-tenant PoCs.
- **Backward Compatibility**: The `Config.Tenancy` string remains the source of truth for selecting the provider, ensuring no changes to `gate.yaml` are required.
