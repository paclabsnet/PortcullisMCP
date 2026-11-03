# MCP Activity Log Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver full auditability and forensic traceability for MCP tool interactions across Portcullis by replacing legacy HTTP `decision_log` with an SIEM-oriented `mcp_activity_log` in Keep, capturing agent metadata via Gate's MCP session handshake, and recording correlated request and response JSON-lines with automated rotation and configurable payload truncation.

**Architecture:** Gate extracts `clientInfo` during the MCP `initialize` handshake and forwards it on `EnrichedMCPRequest.Agent`. Keep processes incoming tool calls and emits paired, correlated JSON-lines audit records through a lock-free, bounded in-memory channel to a background worker writing to a rotating file sink (`lumberjack.v2`) or stdout. Pre-enqueue truncation and body-preserving capped tee decoding prevent memory exhaustion while maintaining full forensic fidelity when truncation is disabled.

**Tech Stack:** Go 1.25, `github.com/modelcontextprotocol/go-sdk/mcp`, `gopkg.in/natefinch/lumberjack.v2`, standard library `log/slog`, `sync/atomic`.

**Spec:** `docs/development/specs/2026-11-03-mcp-activity-log-design.md`

## Global Constraints
- Target Go version: 1.25.0 (`go.mod`).
- Dependencies: add `gopkg.in/natefinch/lumberjack.v2` for rotating log file management.
- Configuration defaults: `enabled: false`, `file: "/var/log/portcullis/mcp-activity.log"`, `max_size_mb: 100`, `max_backups: 10`, `max_age_days: 30`, `compress: false`, `include_pdp_decision: false`, `truncate_payloads: false`, `max_payload_bytes: 4096`, `buffer_size: 10000`.
- Memory safety: channel buffer bounded by `buffer_size` (10,000); drops on full via non-blocking send; no artificial response ceiling when `truncate_payloads: false`.
- Channel lifecycle: `ActivityLogger` channel is **never closed** to prevent send-on-closed panics; shutdown uses atomic flags and dedicated control channel.
- Decommission: legacy `decision_log` HTTP endpoints and buffer forwarders in Gate and Keep must be completely removed.

## Review Focus
1. **Missing or nil `clientInfo` during MCP `initialize`**: Must safely default `name` and `version` to `"unknown"` without nil pointer panics.
2. **Multi-byte UTF-8 boundary cutting**: Truncation slicing at `max_payload_bytes` must step backward to rune boundaries to never emit broken UTF-8 byte sequences or `\uFFFD`.
3. **Concurrent shutdown race under load**: Simultaneous calls to `LogRequest`/`LogResponse` and `Shutdown` must never panic or deadlock.
4. **Sink disk write failure**: Lumberjack write failures must be logged to slog, increment drop metric, and not crash Keep or stall proxy traffic.
5. **Escalation retry correlation**: Initial `escalation_pending` response and subsequent retry request must both log `escalation_jti` across distinct trace IDs.

---

### Task 1: Shared Types & Dependency Setup

**Files:**
- Modify: `go.mod`
- Modify: `internal/shared/types.go:115-140`
- Test: `internal/shared/types_test.go` (or inline validation)

**Interfaces:**
- Produces:
  ```go
  type AgentInfo struct {
      Name    string `json:"name"`
      Version string `json:"version"`
  }
  // Added to EnrichedMCPRequest:
  // Agent AgentInfo `json:"agent"`
  ```

- [ ] **Step 1: Write test verifying `AgentInfo` JSON serialization in `EnrichedMCPRequest`**

Create/update `internal/shared/types_test.go`:
```go
func TestEnrichedMCPRequest_AgentSerialization(t *testing.T) {
    req := EnrichedMCPRequest{
        ServerName: "db-mcp",
        ToolName:   "query",
        Agent: AgentInfo{
            Name:    "claude-code",
            Version: "1.0.0",
        },
    }
    data, err := json.Marshal(req)
    if err != nil {
        t.Fatalf("marshal failed: %v", err)
    }
    var decoded EnrichedMCPRequest
    if err := json.Unmarshal(data, &decoded); err != nil {
        t.Fatalf("unmarshal failed: %v", err)
    }
    if decoded.Agent.Name != "claude-code" || decoded.Agent.Version != "1.0.0" {
        t.Fatalf("expected Agent claude-code:1.0.0, got %+v", decoded.Agent)
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test -v ./internal/shared -run TestEnrichedMCPRequest_AgentSerialization`
Expected: FAIL (unknown field `Agent` or `AgentInfo`)

- [ ] **Step 3: Add `lumberjack.v2` dependency and define `AgentInfo`**

Run: `go get gopkg.in/natefinch/lumberjack.v2`
Add `AgentInfo` struct to `internal/shared/types.go` and add `Agent AgentInfo json:"agent"` to `EnrichedMCPRequest`.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test -v ./internal/shared -run TestEnrichedMCPRequest_AgentSerialization`
Expected: PASS

- [ ] **Step 5: Verify all packages still compile**

Run: `go build ./...`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add go.mod go.sum internal/shared/types.go internal/shared/types_test.go
git commit -m "feat(shared): add AgentInfo to EnrichedMCPRequest and import lumberjack"
```

---

### Task 2: Configuration Schemas in Shared and Keep

**Files:**
- Modify: `internal/shared/config/unified.go`
- Modify: `internal/keep/config.go`
- Test: `internal/keep/config_test.go`
- Test: `internal/shared/config/loader_test.go`

**Interfaces:**
- Produces:
  ```go
  type MCPActivityLogConfig struct {
      Enabled            bool   `yaml:"enabled"`
      File               string `yaml:"file"`
      MaxSizeMB          int    `yaml:"max_size_mb"`
      MaxBackups         int    `yaml:"max_backups"`
      MaxAgeDays         int    `yaml:"max_age_days"`
      Compress           *bool  `yaml:"compress"`             // nil = omitted (default: true)
      IncludePDPDecision *bool  `yaml:"include_pdp_decision"` // nil = omitted (default: true)
      TruncatePayloads   bool   `yaml:"truncate_payloads"`
      MaxPayloadBytes    int    `yaml:"max_payload_bytes"`
      BufferSize         int    `yaml:"buffer_size"`
  }
  func (c *MCPActivityLogConfig) IsCompressed() bool
  func (c *MCPActivityLogConfig) ShouldIncludePDPDecision() bool
  func (c *MCPActivityLogConfig) ApplyDefaults()
  ```

- [ ] **Step 1: Write configuration parsing tests with valid fixtures for defaults, omitted booleans, and explicit true**

Add to `internal/keep/config_test.go`:
```go
func TestKeepConfig_MCPActivityLog(t *testing.T) {
    t.Run("omitted booleans resolve to false defaults", func(t *testing.T) {
        yamlConfig := `
mode: "dev"
server:
  endpoints:
    main:
      listen: "localhost:8080"
responsibility:
  policy:
    strategy: "opa"
    config:
      endpoint: "http://opa:8181"
identity:
  strategy: "passthrough"
mcp_activity_log:
  enabled: true
`
        tmp, err := os.CreateTemp("", "keep-activity-*.yaml")
        if err != nil {
            t.Fatalf("temp file: %v", err)
        }
        defer os.Remove(tmp.Name())
        if _, err := tmp.Write([]byte(yamlConfig)); err != nil {
            t.Fatalf("write temp: %v", err)
        }
        tmp.Close()

        cfg, _, err := LoadConfig(context.Background(), tmp.Name())
        if err != nil {
            t.Fatalf("LoadConfig failed: %v", err)
        }
        act := cfg.MCPActivityLog
        if !act.Enabled {
            t.Errorf("expected enabled=true")
        }
        if act.File != "/var/log/portcullis/mcp-activity.log" {
            t.Errorf("expected default file, got %q", act.File)
        }
        if act.MaxSizeMB != 100 || act.MaxBackups != 10 || act.MaxAgeDays != 30 {
            t.Errorf("unexpected rotation defaults: %+v", act)
        }
        if act.IsCompressed() {
            t.Errorf("expected omitted compress to resolve false by default")
        }
        if act.ShouldIncludePDPDecision() {
            t.Errorf("expected omitted include_pdp_decision to resolve false by default")
        }
        if act.TruncatePayloads {
            t.Errorf("expected truncate_payloads default false")
        }
        if act.MaxPayloadBytes != 4096 || act.BufferSize != 10000 {
            t.Errorf("unexpected payload/buffer defaults: %+v", act)
        }
    })

    t.Run("explicit true booleans are preserved", func(t *testing.T) {
        yamlConfig := `
mode: "dev"
server:
  endpoints:
    main:
      listen: "localhost:8080"
responsibility:
  policy:
    strategy: "opa"
    config:
      endpoint: "http://opa:8181"
identity:
  strategy: "passthrough"
mcp_activity_log:
  enabled: true
  compress: true
  include_pdp_decision: true
`
        tmp, err := os.CreateTemp("", "keep-activity-true-*.yaml")
        if err != nil {
            t.Fatalf("temp file: %v", err)
        }
        defer os.Remove(tmp.Name())
        if _, err := tmp.Write([]byte(yamlConfig)); err != nil {
            t.Fatalf("write temp: %v", err)
        }
        tmp.Close()

        cfg, _, err := LoadConfig(context.Background(), tmp.Name())
        if err != nil {
            t.Fatalf("LoadConfig failed: %v", err)
        }
        if !cfg.MCPActivityLog.IsCompressed() {
            t.Errorf("expected explicit compress: true to be preserved")
        }
        if !cfg.MCPActivityLog.ShouldIncludePDPDecision() {
            t.Errorf("expected explicit include_pdp_decision: true to be preserved")
        }
    })
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test -v ./internal/keep -run TestKeepConfig_MCPActivityLog`
Expected: FAIL (`MCPActivityLog` undefined)

- [ ] **Step 3: Implement `MCPActivityLogConfig` with presence-aware pointer booleans and defaults**

- In `internal/shared/config/unified.go`, define `MCPActivityLogConfig` with `Compress *bool` and `IncludePDPDecision *bool`.
- Implement `IsCompressed() bool` and `ShouldIncludePDPDecision() bool`.
- Implement `ApplyDefaults()` to populate `File: "/var/log/portcullis/mcp-activity.log"`, `MaxSizeMB: 100`, `MaxBackups: 10`, `MaxAgeDays: 30`, `MaxPayloadBytes: 4096`, `BufferSize: 10000` while preserving `*bool` states.
- Mark `DecisionLogConfig` as deprecated; if `DecisionLog.Enabled` is encountered in config, log slog warning: `"decision_log is deprecated and ignored; use mcp_activity_log"`.
- Wire `MCPActivityLog MCPActivityLogConfig yaml:"mcp_activity_log"` into Keep's `Config` struct.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test -v ./internal/keep -run TestKeepConfig_MCPActivityLog`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/shared/config/unified.go internal/keep/config.go internal/keep/config_test.go
git commit -m "feat(config): add mcp_activity_log config schema with defaults"
```

---

### Task 3: Core Activity Log Engine (`internal/keep/activitylog/`)

**Files:**
- Create: `internal/keep/activitylog/entry.go`
- Create: `internal/keep/activitylog/truncation.go`
- Create: `internal/keep/activitylog/sink.go`
- Create: `internal/keep/activitylog/logger.go`
- Test: `internal/keep/activitylog/logger_test.go`

**Interfaces:**
- Produces:
  ```go
  type ActivitySink interface {
      WriteEntry(entry []byte) error
      Close() error
  }
  type ActivityLogger struct { ... }
  func New(cfg MCPActivityLogConfig, sink ActivitySink) *ActivityLogger
  func (al *ActivityLogger) Enabled() bool
  func (al *ActivityLogger) LogRequest(req *RequestEntry)
  func (al *ActivityLogger) LogResponse(resp *ResponseEntry)
  func (al *ActivityLogger) LogMalformedRequest(mal *MalformedRequestEntry)
  func (al *ActivityLogger) Shutdown(ctx context.Context) error
  func (al *ActivityLogger) Stats() map[string]any
  ```

- [ ] **Step 1: Write comprehensive unit tests for activity log engine**

Create `internal/keep/activitylog/logger_test.go`:
- Test 1: JSON serialization of `mcp_request` and `mcp_response` including `remote_addr`, `timestamp`, `agent`.
- Test 2: When `include_pdp_decision: false`, verify `pdp_decision` and `pdp_reason` fields are completely omitted from JSON.
- Test 3: Truncation with multi-byte UTF-8 slicing: verify cutting a 3-byte rune steps back cleanly without emitting `\uFFFD`, and populates `_truncated: true`, `_bytes: len`, `_preview: string`.
- Test 4: `CappedTeeReader`: verify decoder reads full payload while buffer only captures up to `maxPayloadBytes`.
- Test 5: Full queue drop behavior: send beyond `buffer_size` on stalled sink; verify non-blocking send and `droppedCount` increment.
- Test 6: Sink write failure: mock sink returning `io.ErrClosedPipe` must log slog error, increment `sinkErrorCount`, and not panic.
- Test 7: Concurrency & Idempotent Shutdown: 10 goroutines hammering `LogRequest`/`LogResponse` while 3 goroutines call `Shutdown`; verify zero panics, safe channel drain, and idempotent return.
- Test 8: Nil & Disabled Safety: call `LogRequest`, `LogResponse`, `LogMalformedRequest`, and `Shutdown` on a nil `*ActivityLogger` and on an initialized logger with `cfg.Enabled == false`; verify immediate return with zero panics, zero allocations, and zero worker goroutines.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test -v ./internal/keep/activitylog`
Expected: FAIL (package does not exist)

- [ ] **Step 3: Implement `entry.go`, `truncation.go`, `sink.go`, and `logger.go`**

1. `entry.go`:
   - `RequestEntry`: `timestamp`, `event: "mcp_request"`, `remote_addr`, `session_id`, `trace_id`, `user_id`, `agent`, `server_name`, `tool_name`, `arguments`, `pdp_decision` (pointer or string with omitempty), `pdp_reason` (omitempty), `escalation_jti` (omitempty).
   - `ResponseEntry`: `timestamp`, `event: "mcp_response"`, `remote_addr`, `session_id`, `trace_id`, `user_id`, `agent`, `server_name`, `tool_name`, `duration_ms`, `status`, `result` (any), `error` (string, omitempty), `escalation_jti` (omitempty), `workflow_reference` (omitempty).
   - `MalformedRequestEntry`: `timestamp`, `event: "mcp_malformed_request"`, `remote_addr`, `trace_id`, `error`, `raw_preview`.
2. `truncation.go`:
   - `TruncatePayload(data []byte, maxBytes int) any`:
     If `len(data) <= maxBytes`, return `json.RawMessage(data)`.
     Slice `sub := data[:maxBytes]`. For `!utf8.Valid(sub)`, step back up to 3 bytes: `sub = sub[:len(sub)-1]`.
     Return struct `{ Truncated: true, Bytes: len(data), Preview: string(sub) }` with JSON tags `_truncated`, `_bytes`, `_preview`.
   - `CappedTeeReader(r io.Reader, limit int)`:
     Reads through while buffering first `limit` bytes.
3. `sink.go`:
   - `FileSink`: wraps `lumberjack.Logger` (`Filename`, `MaxSize`, `MaxBackups`, `MaxAge`, `Compress`). Appends newline if missing.
   - `StdoutSink`: writes directly to `os.Stdout`.
4. `logger.go`:
   - Fixed buffered channel `chan []byte` (capacity `cfg.BufferSize`).
   - `closed atomic.Bool`, `droppedCount atomic.Int64`, `sinkErrorCount atomic.Int64`.
   - `LogRequest`, `LogResponse`, `LogMalformedRequest`:
     Check `al.closed.Load()`. If true, increment `droppedCount` and return.
     Marshal to single-line JSON.
     Non-blocking send to channel: `select { case al.ch <- line: default: al.droppedCount.Add(1) }`.
   - Worker goroutine: reads `al.ch`, writes to `sink.WriteEntry()`. If sink fails, logs to `slog.Error("activity log sink write failed", "error", err)` and increments `sinkErrorCount`.
   - `Shutdown(ctx context.Context) error`:
     `shutdownOnce.Do`: set `al.closed.Store(true)`, close `al.stopWorker`, worker drains remaining items in `al.ch`, wait on `al.workerDone` or `<-ctx.Done()`, close sink.

- [ ] **Step 4: Run tests to verify all pass**

Run: `go test -v -race ./internal/keep/activitylog`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/keep/activitylog/
git commit -m "feat(keep): implement mcp_activity_log engine with lumberjack rotation and pre-enqueue truncation"
```

---

### Task 4: Gate SessionStore Agent Info & Multi-Tenant Identity Discovery

**Files:**
- Modify: `internal/gate/session_store.go`
- Modify: `internal/gate/memory_session_store.go`
- Modify: `internal/gate/redis_session_store.go`
- Modify: `internal/gate/mcp_http.go`
- Modify: `internal/gate/server.go`
- Modify: `internal/gate/multi_tenant_provider.go`
- Modify: `internal/gate/forwarder.go`
- Modify: `internal/gate/error_mapper.go`
- Modify: `internal/gate/config.go`
- Delete: `internal/gate/decision_logger.go`
- Test: `internal/gate/memory_session_store_test.go`
- Test: `internal/gate/redis_session_store_test.go`
- Test: `internal/gate/server_test.go`
- Test: `internal/gate/mcp_http_test.go`
- Test: `internal/gate/multi_tenant_test.go`
- Test: `internal/gate/forwarder_test.go`
- Test: `internal/gate/server_tool_test.go`
- Test: `internal/gate/server_escalation_test.go`
- Test: `internal/gate/gate_test_helpers_test.go`

**Interfaces:**
- Consumes: `shared.AgentInfo`, `shared.EnrichedMCPRequest`
- Produces:
  ```go
  // Extended SessionStore:
  type SessionStore interface {
      SaveSession(ctx context.Context, sessionID, userID string, state []byte) error
      SaveSessionIfAbsent(ctx context.Context, sessionID, userID string, state []byte) (bool, error)
      GetSession(ctx context.Context, sessionID string) (state []byte, userID string, err error)
      DeleteSession(ctx context.Context, sessionID string) error

      SaveAgentInfo(ctx context.Context, sessionID string, agent shared.AgentInfo) error
      GetAgentInfo(ctx context.Context, sessionID string) (shared.AgentInfo, error)
  }
  ```
- Ensures: `req.Agent` is correctly populated on all tool calls forwarded to Keep in both single-tenant and multi-tenant modes.

- [ ] **Step 1: Write tests for `SessionStore.SaveAgentInfo` and `GetAgentInfo`**

In `internal/gate/memory_session_store_test.go` and `internal/gate/redis_session_store_test.go`:
- Test saving `shared.AgentInfo{Name: "claude-code", Version: "1.0.0"}` under `sessionID`.
- Test retrieving `AgentInfo` by `sessionID` returns exact values.
- Test retrieving `AgentInfo` for nonexistent session returns `ErrSessionNotFound`.

- [ ] **Step 2: Run session store tests to verify they fail**

Run: `go test -v ./internal/gate -run TestMemorySessionStore_AgentInfo`
Expected: FAIL (`SaveAgentInfo` undefined)

- [ ] **Step 3: Implement `SaveAgentInfo` and `GetAgentInfo` in `SessionStore`**

- Update `internal/gate/session_store.go` interface.
- In `internal/gate/memory_session_store.go`: add `agent shared.AgentInfo` to `memorySession` struct and implement `SaveAgentInfo` and `GetAgentInfo` under mutex lock.
- In `internal/gate/redis_session_store.go`: add `Agent shared.AgentInfo json:"agent,omitempty"` to `redisSessionValue` struct; update JSON serialization and implement `SaveAgentInfo` and `GetAgentInfo`.

- [ ] **Step 4: Run session store tests to verify they pass**

Run: `go test -v ./internal/gate -run "TestMemorySessionStore_AgentInfo|TestRedisSessionStore_AgentInfo"`
Expected: PASS

- [ ] **Step 5: Write tests for Multi-Tenant SDK session ID capture and tool call propagation**

In `internal/gate/mcp_http_test.go` and `internal/gate/server_test.go`:
- Test single-tenant: MCP `initialize` with `clientInfo: {"name": "claude-code", "version": "1.0.0"}`; execute `tools/call`; verify `EnrichedMCPRequest.Agent` has name and version.
- Test single-tenant missing `clientInfo`: defaults to `"unknown"`.
- Test multi-tenant:
  1. Send HTTP POST `/mcp` with `initialize` and `clientInfo: {"name": "cursor-agent", "version": "0.42.0"}` with NO `Mcp-Session-Id` header.
  2. Capture the returned `Mcp-Session-Id` response header set by the MCP SDK.
  3. Send subsequent HTTP POST `/mcp` with `tools/call` bearing `Mcp-Session-Id: <captured-session-id>`.
  4. Assert the forwarded `EnrichedMCPRequest.Agent` received by Keep forwarder matches `"cursor-agent"` and `"0.42.0"`.

- [ ] **Step 6: Run tests to verify they fail**

Run: `go test -v ./internal/gate -run TestMCPHTTP_MultiTenantAgentDiscovery`
Expected: FAIL

- [ ] **Step 7: Implement SDK response header interceptor, Gate agent propagation, and migrate legacy Gate callers**

1. In `internal/gate/server.go`:
   - Register receiving middleware on `Gate.server` to capture `clientInfo` on `initialize`.
   - Store in `singleTenantAgent` for single-tenant mode, or record in request context for multi-tenant HTTP mode.
   - Remove `logger DecisionLogger` from `Gate` struct, `New()`, and `Gate.Run` worker startup.
   - In `handleToolCall`: remove calls to `g.logger.Log(...)`.
   - Remove `SendLogs` from `KeepForwarder` interface.
2. In `internal/gate/mcp_http.go`:
   - Wrap `w http.ResponseWriter` with an interceptor in `MCPHTTPHandler.ServeHTTP` to capture the SDK's outgoing `Mcp-Session-Id` header.
   - When the SDK completes `initialize`, retrieve the SDK's actual returned session ID and save the captured `AgentInfo` into `p.sessions.SaveAgentInfo(ctx, sdkSessionID, agent)`.
3. In `internal/gate/error_mapper.go`:
   - Remove calls to `g.logger.Log(DecisionLogEntry{...})` in `policyErrToResult`.
4. In `internal/gate/multi_tenant_provider.go`:
   - Update `NewMultiTenantProvider(tokenHeader string, sessions SessionStore)` signature and struct to remove the `logger DecisionLogger` parameter and field.
5. In `internal/gate/forwarder.go`:
   - Remove `SendLogs(ctx, entries)` method and payload types.
6. In `internal/gate/config.go`:
   - Deprecate/remove `DecisionLogBatchConfig` and references in `ResponsibilityConfig`.
7. Delete `internal/gate/decision_logger.go`.
8. Migrate Gate test helpers and test fixtures:
   - In `internal/gate/gate_test_helpers_test.go`: remove `captureLogger`.
   - In `internal/gate/forwarder_test.go`: remove `TestForwarder_SendLogs` tests.
   - In `internal/gate/server_tool_test.go`: remove `TestBatchDecisionLogger_Worker` and remove `SendLogs` from mock forwarders.
   - In `internal/gate/multi_tenant_test.go` and `internal/gate/multi_tenant_escalation_test.go`: update `NewMultiTenantProvider` call sites (remove `logger` arg) and remove legacy decision log assertions.
   - In `internal/gate/server_escalation_test.go`: remove assertions on legacy `captureLogger.entries`.

- [ ] **Step 8: Run Gate tests to verify all pass**

Run: `go test -v -race ./internal/gate/...`
Expected: PASS

- [ ] **Step 9: Commit**

```bash
git add internal/gate/
git rm internal/gate/decision_logger.go
git commit -m "feat(gate): associate agent metadata with SDK Mcp-Session-Id and remove legacy decision logger callers"
```

---

### Task 5: Keep Server Activity Log Integration & Decommission Legacy Decision Logger

**Files:**
- Modify: `internal/keep/server.go`
- Modify: `internal/keep/config.go`
- Modify: `internal/keep/alias_hidden_test.go`
- Modify: `internal/keep/auth_test.go`
- Modify: `internal/keep/identity_test.go`
- Modify: `internal/keep/server_health_test.go`
- Modify: `internal/keep/server_test.go`
- Modify: `internal/keep/server_validation_test.go`
- Delete: `internal/keep/decisionlog.go`
- Delete: `internal/keep/decisionlog_test.go`
- Create: `internal/keep/server_activity_test.go`

**Interfaces:**
- Consumes: `activitylog.ActivityLogger`, `shared.EnrichedMCPRequest`
- Emits: `mcp_request`, `mcp_response`, and `mcp_malformed_request` records across all execution paths.

- [ ] **Step 1: Write comprehensive server activity log integration tests**

Create `internal/keep/server_activity_test.go`:
- Test `handleCall` with `mcp_activity_log.enabled: false` (the default): verify valid tool execution, malformed JSON bodies, identity normalization errors, and PDP denials execute safely with zero panics, no log file creation, and normal HTTP status codes.
- Test `handleCall` with malformed JSON body: verify HTTP 400 and `mcp_malformed_request` record emitted with `raw_preview`.
- Test `handleCall` with identity normalization failure: verify HTTP 401/403, `mcp_request` record (user: `"unauthenticated"`), and synthetic `mcp_response` record (`status: "error"`).
- Test `handleCall` with hidden tool name: verify HTTP 403 deny, `mcp_request` record (`pdp_decision: "deny"`), and synthetic `mcp_response` record (`status: "denied"`).
- Test `handleCall` with PDP error (timeout/unreachable): verify HTTP 503, `mcp_request` record, and synthetic `mcp_response` record (`status: "error"`), even if `include_pdp_decision: false`.
- Test `handleCall` with PDP escalation: verify HTTP 202, `mcp_request`, and synthetic `mcp_response` (`status: "escalation_pending"`, `escalation_jti`).
- Test `handleCall` escalation retry: verify `mcp_request` includes presented `escalation_jti` and terminal `mcp_response` (`status: "success"`).
- Test `handleCall` successful tool call (`result.IsError == false`): verify paired `mcp_request` and `mcp_response` with `status: "success"`, matching `trace_id`, `session_id`, `remote_addr`, duration, and backend result.
- Test `handleCall` tool-level error (`err == nil` but `result.IsError == true`): verify HTTP 200 returned to caller, but `mcp_response` records `status: "error"`, retains the full `result` object with error content, and records `error: "tool returned error..."` rather than falsely recording `status: "success"`.

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test -v ./internal/keep -run TestServerActivityLog`
Expected: FAIL

- [ ] **Step 3: Update Keep `Server`, migrate test fixtures, and remove `DecisionLogger`**

1. In `internal/keep/config.go`:
   - Remove `DecisionLog cfgloader.DecisionLogConfig` field and decoding.
   - Wire `MCPActivityLog cfgloader.MCPActivityLogConfig`.
2. In `internal/keep/server.go`:
   - Remove `decisionLog *DecisionLogger` field from `Server`.
   - Remove `POST /log` handler and `s.handleLog` method.
   - Remove all legacy `s.decisionLog.Log(...)` calls.
   - Add `activityLog *activitylog.ActivityLogger` field. Always initialize via `s.activityLog = activitylog.New(cfg.MCPActivityLog, sink)` in `NewServer` (creating a no-op instance with no goroutines when `enabled: false` so `s.activityLog` is never nil).
   - In `handleCall`:
     - Check `if s.activityLog.Enabled()` before wrapping `r.Body` with `cappedTeeReader`. When disabled (default), `r.Body` passes directly to `json.NewDecoder` without tee wrapping overhead.
     - If JSON decoding, version check, or header check fails: call `s.activityLog.LogMalformedRequest(...)`.
     - If `normalizer.Normalize` fails: call `s.activityLog.LogRequest(...)` and synthetic `LogResponse(...)` with status `"error"`.
     - If `router.IsHiddenToolName` is true: call `s.activityLog.LogRequest(...)` and synthetic `LogResponse(...)` with status `"denied"`.
     - After PDP evaluation: call `s.activityLog.LogRequest(...)`.
     - If PDP returns error: call synthetic `LogResponse(...)` with status `"error"`.
     - If PDP returns deny: call synthetic `LogResponse(...)` with status `"denied"`.
     - If PDP returns escalate/workflow: call synthetic `LogResponse(...)` with status `"escalation_pending"`, `escalation_jti`, and `wfRef`.
     - On backend execution (`router.CallTool`):
       - If `err != nil`: call `LogResponse(...)` with `status: "error"`, `error: "backend tool call failed: " + err.Error()`, and `result: nil`.
       - If `err == nil && result != nil && result.IsError`: call `LogResponse(...)` with `status: "error"`, `error: "tool returned error"`, and `result: result` (retaining full tool error content).
       - If `err == nil && (result == nil || !result.IsError)`: call `LogResponse(...)` with `status: "success"`, duration, and `result: result`.
   - In Keep server shutdown sequence: call `s.activityLog.Shutdown(ctx)`.
3. Migrate Keep test fixtures:
   - In `internal/keep/alias_hidden_test.go`, `auth_test.go`, `identity_test.go`, `server_health_test.go`, `server_test.go`, and `server_validation_test.go`:
     Replace `decisionLog: NewDecisionLogger(...)` with `activityLog: activitylog.New(cfgloader.MCPActivityLogConfig{Enabled: false}, nil)`.
   - In `internal/keep/server_validation_test.go`: remove tests exercising the decommissioned `POST /log` endpoint (`TestServer_Log_Validation`, etc.).
4. Delete `internal/keep/decisionlog.go` and `internal/keep/decisionlog_test.go`.

- [ ] **Step 4: Run tests to verify all pass**

Run: `go test -v -race ./internal/keep -run TestServerActivityLog`
Expected: PASS

- [ ] **Step 5: Run all Keep unit tests**

Run: `go test -v ./internal/keep/...`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add internal/keep/
git rm internal/keep/decisionlog.go internal/keep/decisionlog_test.go
git commit -m "feat(keep): integrate mcp_activity_log, migrate test fixtures, and remove legacy decision log"
```

---

### Task 6: End-to-End Integration & Workspace Verification

**Files:**
- Create: `internal/keep/activity_e2e_test.go`
- Modify: `docs/roadmap.md` (mark Phase 3 activity log task complete)

**Interfaces:**
- Validates the complete pipeline: MCP Client -> Gate -> Keep -> Mock Backend -> File Sink with rotation.

- [ ] **Step 1: Write End-to-End integration test**

Create `internal/keep/activity_e2e_test.go`:
- Spin up Keep with `mcp_activity_log` configured to write to a temporary file with a small `max_size_mb`.
- Dispatch simulated tool calls from a client session.
- Read and unmarshal output lines from the log file:
  - Verify every line is valid single-line JSON.
  - Verify `event: "mcp_request"` and `event: "mcp_response"` pairs share `trace_id` and `session_id`.
  - Verify `agent.name` and `agent.version` match client info.
  - Verify `remote_addr` is present on all records.
  - Verify `_truncated`, `_bytes`, and `_preview` formatting when truncation is active.
- Verify file rotation triggers when payload volume exceeds rotation threshold.

- [ ] **Step 2: Run End-to-End test**

Run: `go test -v -race ./internal/keep -run TestActivityLog_EndToEnd`
Expected: PASS

- [ ] **Step 3: Run entire project test suite**

Run: `go test -v ./...`
Expected: ALL PASS

- [ ] **Step 4: Update roadmap document**

Update `docs/roadmap.md` to update the status of the MCP Activity Log task from planned to completed.

- [ ] **Step 5: Commit**

```bash
git add internal/keep/activity_e2e_test.go docs/roadmap.md
git commit -m "test(keep): add end-to-end activity log test and update roadmap"
```
