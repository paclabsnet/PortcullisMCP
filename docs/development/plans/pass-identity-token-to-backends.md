# Plan: Pass Identity Token to Backend MCPs

This plan outlines the implementation for passing the user's raw identity token from Keep to backend MCP servers via HTTP headers or request body injection.

## 1. Goal
Enable enterprise MCP backends to identify the end-user by providing the raw identity token in every tool call.

## 2. Configuration Schema Changes
Update `BackendConfig` in `internal/keep/config.go` to include the new injection settings.

```go
type BackendConfig struct {
    // ... existing fields ...
    IdentityHeader string `yaml:"identity_header"`
    IdentityPath   string `yaml:"identity_path"`
}
```

### 2.1. Configuration Validation
Update `(c *Config) Validate()` in `internal/keep/config.go` to ensure secure and robust configuration:
- **Value Constraints**: Ensure `IdentityHeader` and `IdentityPath` (if provided) are not empty or whitespace-only.
- **Forbidden Headers**: Reject any `IdentityHeader` that matches `shared.IsForbiddenHeader`. This prevents backends from being configured to overwrite protocol-critical headers like `Host` or `Content-Length`.
- **Path Validation**: Reject `IdentityPath` values with empty segments (e.g., `a..b`, `.a`, `a.`) or invalid characters to ensure reliable injection.
- **Precedence Documentation**: Explicitly document that `IdentityHeader` takes precedence over client-forwarded headers if they share the same name.

## 3. Data Flow Changes

### 3.1. Internal Request State
- **Context Key**: Define a private context key for the raw identity token in `internal/keep/server.go` (or `shared`).
- **Context Injection**: In `Server.handleCall`, after successful identity normalization, inject `rawReq.UserIdentity.RawToken` into the request context.
- **AuthorizedRequest Update**: Update `AuthorizedRequest` in `internal/keep/request.go` to carry the `RawToken` for easier access during tool call routing.

**Mandate**: The identity token MUST NOT be stored on `backendConn`, `mcp.ClientSession`, or any other shared state. It must always be retrieved from the per-request context or the `AuthorizedRequest` stack to ensure multi-tenant safety.

### 3.2. Header Injection (HTTP/SSE only)
Modify `headerInjectingRoundTripper.RoundTrip` in `internal/keep/router.go`:
- **Transport Scope**: Note that header injection ONLY applies to `http` and `sse` backends.
- If `conn.cfg.IdentityHeader` is non-empty, extract the raw identity token from `req.Context()`.
- **Override Precedence**: Inject the token into the outgoing request header, overwriting any forwarded client header of the same name.

### 3.3. Body Injection (All Transports)
Modify `Router.CallTool` in `internal/keep/router.go`:
- **Transport Scope**: Body injection applies to ALL backend types (`stdio`, `http`, `sse`).
- **Defensive Copying**: To prevent the identity token from leaking into asynchronous decision logs, `CallTool` MUST create a shallow copy of the `args` map before performing any injection.
- If `conn.cfg.IdentityPath` is non-empty, inject the raw identity token into the **copy** of the `args` map.
- The implementation will handle nested paths (e.g., `a.b.c`) and ensure the injection overrides any existing value at that path.

**Privacy Mandate**: The original `args` map stored in the `AuthorizedRequest` MUST NOT be mutated. This ensures that the `decisionLog`, which may process the request asynchronously, never sees or logs the injected identity token.

## 4. Path Injection Logic
A new helper function `injectAtValue(m map[string]any, path string, value any)` will be implemented:
- Split path by `.`.
- Traverse the map, creating intermediate maps if they don't exist.
- **Intentional Overwrite**: If a non-map value exists where a map is expected (e.g., path is `a.b.c` but `a` is already a string), the existing value will be replaced by a map to ensure the injection can proceed.
- Set the final leaf key to the provided value.

## 5. Verification Plan

### 5.1. Unit Tests (`internal/keep/router_test.go` or `internal/keep/header_forwarding_test.go`)
- **TestHeaderInjection**: Verify `IdentityHeader` is correctly added to outgoing HTTP/SSE requests and overrides client headers.
- **TestBodyInjection**: Verify `IdentityPath` correctly modifies the arguments map across all transports, including nested paths and overrides.
- **TestPathInjectionHelper**: Exhaustive tests for the injection helper (empty path, deep path, type conflicts).
- **TestNoTokenHandling**: Verify that if `RawToken` is empty or missing from the context, no header is added and no body field is injected (preventing accidental empty value injection).
- **TestConfigValidation**: Verify early rejection of invalid/forbidden headers and malformed paths.

### 5.2. Manual Verification
- Use `examples/mock-enterprise-api` (if applicable) or a simple netcat/http echo server to verify the headers and body of the received request.
