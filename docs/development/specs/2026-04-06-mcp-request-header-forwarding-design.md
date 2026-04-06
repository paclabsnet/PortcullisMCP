# MCP Request Header Forwarding

> **Feature:** Enable Gate and Keep to forward HTTP request headers through the MCP request/response cycle, with mandatory forbidden-header enforcement and optional per-backend filtering, allowing backend MCPs to receive identity and context headers sent by clients (e.g., AWS AgentCore).

---

## Goal

Support HTTP-based backend MCPs that expect certain request headers (e.g., `Authorization`, custom tenant headers) to understand client identity and context. Currently, Gate parses headers into `UserIdentity` fields and discards the original headers, preventing Keep from reconstructing the exact header format backends expect.

This feature allows:
1. **Gate** to capture HTTP request headers and forward allowed ones to Keep via `EnrichedMCPRequest`
2. **Keep** to inspect and selectively re-inject those headers when calling backend MCPs
3. **Operators** to safely manage header flow via defaults and per-backend overrides

---

## Design

### Core Principles

1. **Forward by Default**: Client request headers are forwarded end-to-end to backend MCPs by default. The default configuration for `forward_headers` is `["*"]` (all non-forbidden headers).
2. **Strict Protocol Safety**: Hop-by-hop and protocol-critical headers (e.g., `Host`, `Transfer-Encoding`) are **strictly forbidden** and never forwarded, regardless of configuration.
3. **Data-Flow Constraint**: Keep can only re-inject headers that it receives from Gate in the `EnrichedMCPRequest.ClientHeaders` field.
4. **Authorization Preservation**: The original `Authorization` header is preserved and forwarded by default unless explicitly overridden or removed in configuration.
5. **Per-Backend Control**: Keep supports per-backend `forward_headers` (allow) and `drop_headers` (deny) configuration to allow operators to restrict or override the headers sent to specific backends. Gate does not support `drop_headers`; it only decides which incoming headers enter the Portcullis pipeline. Backend-specific suppression is strictly a Keep concern.
6. **Precedence Logic**: Header selection follows a strict order of precedence: **Forbidden (Hard-coded) > DropHeaders (Config Deny) > ForwardHeaders (Config Allow)**.
7. **Context-Driven Injection**: Keep uses request context to pass headers to the outgoing transport, preserving clean service interfaces.
8. **Hot-Reload Consistency**: Changes to the `forward_headers` or `drop_headers` configuration take effect immediately upon config reload without requiring backend reconnection.
9. **Multi-Value Fidelity**: All values for a given header are preserved and forwarded in their original order.
10. **Resource Constraints**: Forwarded headers are subject to strict limits (count, name length, value length, and total size) to prevent resource exhaustion.

### Forbidden Headers (Hard-Coded)

The following headers are **strictly forbidden** from being forwarded. Any attempt to explicitly allowlist them will result in a configuration validation error. They are automatically stripped even if `forward_headers` is set to `["*"]`.

*   **Hop-by-Hop Headers (RFC 2616)**: `Connection`, `Keep-Alive`, `Proxy-Authenticate`, `Proxy-Authorization`, `TE`, `Trailer`, `Transfer-Encoding`, `Upgrade`.
*   **Protocol Integrity Headers**: `Host`, `Content-Length`, `Expect`, `Content-Type`.
*   **Portcullis Internal/Tracing**: `X-Portcullis-*`, `Traceparent`, `Tracestate`.

### Matching Rules

Matching for `forward_headers` and `drop_headers` follows these strict rules:

1.  **Normalization**: All incoming request headers are normalized using `http.CanonicalHeaderKey` (e.g., `x-tenant-id` becomes `X-Tenant-Id`).
2.  **Case Insensitivity**: Patterns in the configuration are matched **case-insensitively** against the normalized header names.
3.  **Global Wildcard**: A pattern of exactly `"*"` matches all headers (except those in the Forbidden list).
4.  **Suffix Wildcard (Prefix Match)**: A pattern ending in `"*"` (e.g., `"x-amzn-*"`) matches any header that starts with the preceding string (e.g., matches `"X-Amzn-RequestId"`).
5.  **Exact Match**: A pattern without a wildcard must match the header name exactly (e.g., `"Authorization"` matches `"Authorization"`).
6.  **Wildcard Restriction**: The `"*"` character is only supported as a **full token** or as a **suffix**. Mid-string or prefix-only wildcards (e.g., `"*-ID"`, `"X-*-ID"`) are not supported and will be treated as literal strings.

### Reload Semantics

In `internal/keep/router.go`, MCP client sessions and their underlying transports are cached and reused across config reloads. To ensure `forward_headers` updates take effect without a restart or reconnection, we will employ the following strategy:

1.  **Stateful RoundTripper**: The `headerInjectingRoundTripper` will not store a static allowlist. Instead, it will hold a reference to the `backendConn` or a thread-safe provider that yields the *current* `ForwardHeaders` and `DropHeaders` for that specific backend.
2.  **Atomic Updates**: When `Router.Reload` is called, it updates the `BackendConfig` within the `backendConn`. Since the `RoundTripper` holds a reference to this live state, the next outgoing request will automatically use the updated filters.

### Changes Overview

#### 1. Shared Types (`internal/shared/types.go`)

Add `ClientHeaders` field to `EnrichedMCPRequest`:

```go
type EnrichedMCPRequest struct {
	// ... existing fields ...
	
	// ClientHeaders are HTTP headers from the original client request to Gate.
	// Header names are in Canonical-Format. Values are unmodified.
	ClientHeaders map[string][]string `json:"client_headers,omitempty"`
}
```

#### 2. Shared Configuration (`internal/shared/config/unified.go`)

Add `ForwardHeaders` to the shared `EndpointConfig`. Default value is `["*"]`.

```go
type EndpointConfig struct {
	// ... existing fields ...
	
	// ForwardHeaders specifies which HTTP request headers are forwarded.
	// Supports exact names, prefixes (x-tenant-*), or "*" for all non-forbidden.
	// Default: ["*"]
	ForwardHeaders []string `yaml:"forward_headers"`
}
```

#### 3. Gate HTTP Handler (`internal/gate/mcp_http.go`)

- **Matching**: Implement the logic defined in "Matching Rules".
- **Normalization**: Use `http.CanonicalHeaderKey` for all map keys.
- **Safety**: Automatically exclude the `ForbiddenHeaders` list regardless of matching patterns.

#### 4. Keep Configuration (`internal/keep/config.go`)

Add `ForwardHeaders` and `DropHeaders` to `BackendConfig`.

```go
type BackendConfig struct {
	// ... existing fields ...
	
	// ForwardHeaders filters which headers from EnrichedMCPRequest are sent to this backend.
	// Default: ["*"]
	ForwardHeaders []string `yaml:"forward_headers"`

	// DropHeaders specifies headers that must NEVER be sent to this backend.
	// Default: []
	DropHeaders []string `yaml:"drop_headers"`
}
```

**New Limits in `LimitsConfig`**:
```go
type LimitsConfig struct {
    // ... existing limits ...
    MaxForwardedHeaders           int `yaml:"max_forwarded_headers"`             // default: 20
    MaxHeaderNameBytes            int `yaml:"max_header_name_bytes"`              // default: 128
    MaxHeaderValueBytes           int `yaml:"max_header_value_bytes"`             // default: 4096
    MaxForwardedHeadersTotalBytes int `yaml:"max_forwarded_headers_total_bytes"` // default: 16384 (16 KB)
}
```

#### 5. Keep Header Injection (`internal/keep/router.go` & `server.go`)

- **RoundTripper**: Intercept outgoing requests, apply precedence logic (**Forbidden > Drop > Forward**), and inject into the outgoing `http.Header`.
- **Validation**: `Keep.handleCall` validates `ClientHeaders` against `LimitsConfig`.

---

## Configuration Examples

### Explicit Blocking at Keep

**Gate forwards everything:**
```yaml
# gate.yaml
server:
  endpoints:
    mcp:
      forward_headers: ["*"]
```

**Keep blocks sensitive context for a specific backend:**
```yaml
# keep.yaml
responsibility:
  mcp_backends:
    - name: "untrusted-external-tool"
      type: "http"
      url: "http://external-service:8080/mcp"
      forward_headers: ["x-public-context-*"]
      drop_headers: 
        - "authorization"
        - "x-tenant-id"
```

---

## Out of Scope

- Response header forwarding (backend to client).
- Header transformation or mutation.
- Forwarding to `localfs` tools (sandbox tools do not receive client headers).

---

## Implementation Tasks

### Task 1: Update Shared Types & Config
- [ ] Add `ClientHeaders map[string][]string` to `EnrichedMCPRequest`.
- [ ] Add `ForwardHeaders` to `EndpointConfig` with default `["*"]`.
- [ ] Implement `ForbiddenHeaders` and `ValidateHeaders()` helper in `internal/shared/validate.go`.

### Task 2: Gate Implementation
- [ ] Update `MCPHTTPHandler` to extract headers into context based on "Forward by Default" logic.
- [ ] Implement wildcard and prefix matching logic for headers.
- [ ] Ensure `Authorization` is preserved by default.

### Task 3: Keep Implementation
- [ ] Update `BackendConfig` with `ForwardHeaders` and `DropHeaders`.
- [ ] Update `LimitsConfig` in `config.go` with explicit fields.
- [ ] Implement the precedence logic (**Forbidden > Drop > Forward**) in the Keep router/transport.
- [ ] Implement `headerInjectingRoundTripper` in `router.go` with dynamic config lookup.

### Task 4: Verification
- [ ] **Default Forwarding Test**: Verify headers are forwarded without explicit configuration.
- [ ] **Wildcard & Prefix Test**: Verify `"*"` and `"X-Tenant-*"` logic matches correctly.
- [ ] **DropHeaders Test**: Verify that `drop_headers` successfully blocks a header.
- [ ] **Resource Limit Test**: Verify that requests exceeding `max_forwarded_headers` or `max_forwarded_headers_total_bytes` are rejected with 400 Bad Request.
- [ ] **Precedence Test**: Verify the hierarchy: Forbidden > Drop > Forward.
- [ ] **Hot-Reload Test**: Verify that updating `drop_headers` takes effect immediately.

---

## Security Considerations

1. **Protocol Integrity**: Hard-coded exclusion of hop-by-hop headers prevents smuggling and connection errors.
2. **Resource Exhaustion**: Strict limits on header count and size (defined in `LimitsConfig`) prevent memory DoS.
3. **Controlled Exposure**: Operators can use `drop_headers` to create "blacklists" for specific backends while maintaining a permissive default posture.
