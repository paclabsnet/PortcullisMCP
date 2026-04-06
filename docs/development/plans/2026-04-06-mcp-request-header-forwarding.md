# MCP Request Header Forwarding Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Enable end-to-end HTTP request header forwarding from clients through Gate and Keep to backend MCPs, with mandatory forbidden-header enforcement, multi-value fidelity, and per-backend overrides.

**Architecture:** 
- **Gate** extracts client headers in its HTTP middleware, normalizes them using `http.CanonicalHeaderKey`, and attaches them to the `EnrichedMCPRequest`. 
- **Keep** receives the headers, validates them against `LimitsConfig`, and injects them into the outgoing request to backend MCPs using a stateful `http.RoundTripper` that supports hot-reloading.
- **Filtering** uses a precedence logic: **Forbidden (Hard-coded) > DropHeaders (Config Deny) > ForwardHeaders (Config Allow)**.

**Tech Stack:** Go (Golang), HTTP/1.1 & HTTP/2, Model Context Protocol (MCP).

---

### File Structure Decisions

- `internal/shared/validate.go`: Centralize forbidden header list and `IsForbiddenHeader` check.
- `internal/shared/headers.go`: Centralize matching logic (`MatchesHeaderPattern`).
- `internal/keep/router.go`: Host the `headerInjectingRoundTripper` and wiring logic.
- `internal/gate/mcp_http.go`: Update middleware for header extraction.

---

### Task 1: Shared Foundation (Types & Hard-coded Safety)

**Files:**
- Modify: `internal/shared/types.go`
- Modify: `internal/shared/config/unified.go`
- Modify: `internal/shared/validate.go`

- [ ] **Step 1: Add `ClientHeaders` to `EnrichedMCPRequest`**
Modify `internal/shared/types.go` to include the new map field.

```go
type EnrichedMCPRequest struct {
	// ... existing fields ...
	ClientHeaders map[string][]string `json:"client_headers,omitempty"`
	// ...
}
```

- [ ] **Step 2: Add `ForwardHeaders` to `EndpointConfig`**
Modify `internal/shared/config/unified.go` to add the configuration field.

```go
type EndpointConfig struct {
	// ... existing fields ...
	ForwardHeaders []string `yaml:"forward_headers"`
}
```

- [ ] **Step 3: Implement Forbidden Headers logic**
Update `internal/shared/validate.go` with the hard-coded safety list.

```go
var ForbiddenHeaders = map[string]bool{
	"Connection":          true,
	"Keep-Alive":          true,
	"Proxy-Authenticate":  true,
	"Proxy-Authorization": true,
	"Te":                  true, // Canonical form of TE
	"Trailer":             true,
	"Transfer-Encoding":   true,
	"Upgrade":             true,
	"Host":                true,
	"Content-Length":      true,
	"Expect":              true,
	"Content-Type":        true,
	"Traceparent":         true,
	"Tracestate":          true,
}

func IsForbiddenHeader(name string) bool {
	if ForbiddenHeaders[http.CanonicalHeaderKey(name)] {
		return true
	}
	return strings.HasPrefix(strings.ToLower(name), "x-portcullis-")
}
```

- [ ] **Step 4: Commit Task 1**
```bash
git add internal/shared/types.go internal/shared/config/unified.go internal/shared/validate.go
git commit -m "feat: shared foundation for header forwarding"
```

---

### Task 2: Matching Logic & Pattern Support

**Files:**
- Create: `internal/shared/headers.go`
- Create: `internal/shared/headers_test.go`

- [ ] **Step 1: Implement `MatchesHeaderPattern`**
Implement wildcard (`*`) and suffix wildcard (`x-tenant-*`) matching.

```go
func MatchesHeaderPattern(pattern, header string) bool {
	pattern = strings.ToLower(pattern)
	header = strings.ToLower(header)
	if pattern == "*" {
		return true
	}
	if strings.HasSuffix(pattern, "*") {
		return strings.HasPrefix(header, strings.TrimSuffix(pattern, "*"))
	}
	return pattern == header
}
```

- [ ] **Step 2: Write unit tests for matching**
Verify exact, prefix, and global wildcard matches.

- [ ] **Step 3: Commit Task 2**
```bash
git add internal/shared/headers.go internal/shared/headers_test.go
git commit -m "feat: header matching logic with wildcard support"
```

---

### Task 3: Gate Extraction Middleware

**Files:**
- Modify: `internal/gate/mcp_http.go`
- Modify: `internal/gate/server.go`
- Test: `internal/gate/mcp_http_test.go`

- [ ] **Step 1: Update `MCPHTTPHandler` extraction**
Extract allowed headers in `ServeHTTP` and store them in the context.

- [ ] **Step 2: Update `Gate.handleToolCall`**
Retrieve `ClientHeaders` from context and populate `EnrichedMCPRequest`.

- [ ] **Step 3: Update `Config.Validate` in Gate**
Ensure `ForwardHeaders` are validated (optional check for obvious forbidden ones).

- [ ] **Step 4: Verify with `internal/gate/mcp_http_test.go`**
Add a test case ensuring headers are extracted into the context correctly.

- [ ] **Step 5: Commit Task 3**
```bash
git add internal/gate/mcp_http.go internal/gate/server.go internal/gate/config.go internal/gate/mcp_http_test.go
git commit -m "feat: gate header extraction and context injection"
```

---

### Task 4: Keep Limits & Routing Foundation

**Files:**
- Modify: `internal/keep/config.go`
- Modify: `internal/keep/server.go`

- [ ] **Step 1: Update `LimitsConfig` and `BackendConfig`**
Add the new resource limits and `DropHeaders`.

```go
type LimitsConfig struct {
	// ... existing ...
	MaxForwardedHeaders           int `yaml:"max_forwarded_headers"`
	MaxHeaderNameBytes            int `yaml:"max_header_name_bytes"`
	MaxHeaderValueBytes           int `yaml:"max_header_value_bytes"`
	MaxForwardedHeadersTotalBytes int `yaml:"max_forwarded_headers_total_bytes"`
}
```

- [ ] **Step 2: Update `Server.handleCall`**
Validate incoming `ClientHeaders` against limits before processing.

- [ ] **Step 3: Commit Task 4**
```bash
git add internal/keep/config.go internal/keep/server.go
git commit -m "feat: keep header limits and configuration"
```

---

### Task 5: Keep Stateful RoundTripper Implementation

**Files:**
- Modify: `internal/keep/router.go`

- [ ] **Step 1: Implement `headerInjectingRoundTripper`**
Implement `RoundTrip` with precedence logic: Forbidden > Drop > Forward.

- [ ] **Step 2: Update `buildBackendTransport`**
Wrap the backend client transport with the new `RoundTripper`, passing a reference to the `backendConn`.

- [ ] **Step 3: Commit Task 5**
```bash
git add internal/keep/router.go
git commit -m "feat: keep header injection via stateful round-tripper"
```

---

### Task 6: End-to-End Verification

**Files:**
- Create: `internal/gate/integration_headers_test.go`

- [ ] **Step 1: Implement full-chain test**
Simulate a request to Gate with headers, ensure they reach a mock backend called by Keep.

- [ ] **Step 2: Verify Hot-Reload**
Test that updating `drop_headers` in a mock config and calling `Router.Reload` takes effect.

- [ ] **Step 3: Final Commit & Cleanup**
```bash
git add internal/gate/integration_headers_test.go
git commit -m "test: end-to-end header forwarding verification"
```
