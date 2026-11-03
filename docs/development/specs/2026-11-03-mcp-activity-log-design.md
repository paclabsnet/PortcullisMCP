# MCP Activity Log Design

## Objective
Provide comprehensive auditability and forensic traceability for Model Context Protocol (MCP) tool interactions across Portcullis. This replaces the legacy, HTTP-batching `decision_log` facility with a dedicated `mcp_activity_log` in Keep. The activity log records correlated request and response JSON-lines with automated file rotation, configurable payload truncation, and enriched agent identity metadata captured by Gate during the MCP protocol initialization handshake.

## Goals & Non-Goals

### Goals
- Capture client agent identity (`name` and `version`) during MCP protocol initialization and propagate it via `EnrichedMCPRequest`.
- Provide paired, correlated JSON-lines audit records (`mcp_request` and `mcp_response`) sharing `trace_id` and `session_id`.
- Automatically emit synthetic response records when PDP denies, halts for escalation, or encounters an evaluation error so every admitted request has a matching terminal response.
- Support robust file rotation with configurable size, retention count, age, and compression.
- Support configurable byte truncation for large request arguments and response payloads.
- Completely remove obsolete `decision_log` HTTP batching code and endpoints.

### Non-Goals
- **Gate Fast-Path Auditing**: Local filesystem tool calls handled via Gate's local fast-path (`localfs`) will not be forwarded or logged in `mcp_activity_log` in this phase (consistent with the roadmap). Gate fast-path auditing will be addressed in a future enhancement.
- **Payload Redaction (Deferred to Future Capability)**:
  - *Rationale*: Tool arguments and responses in MCP contain free-form text, code diffs, database query results, and arbitrarily nested JSON. Naive regex redaction frequently causes false positives (mangling legitimate code or SQL queries) and false negatives (missing obfuscated secrets), while deep semantic scanning introduces significant CPU latency on the proxy hot path. In enterprise deployments, SIEM collectors (Splunk, Datadog, Cribl, OpenTelemetry Collector) typically perform standardized DLP/PII filtering downstream.
  - *Future-Proof Architecture*: The decoupled worker and `ActivitySink` interface provide a dedicated transformation point where an optional redaction pipeline (regex patterns, JSONPath masking, or external DLP filter) can be cleanly inserted in a future phase without modifying Gate or Keep request handling.

## Key Files & Context
- `internal/shared/types.go` — `AgentInfo` struct and `EnrichedMCPRequest` update.
- `internal/shared/config/unified.go` — New `MCPActivityLogConfig` schema; deprecation and cleanup of `DecisionLogConfig`.
- `internal/gate/server.go` — Extract `clientInfo` from MCP `initialize` request via middleware, store in session, populate `AgentInfo` on `EnrichedMCPRequest`, and remove `DecisionLogger` references.
- `internal/gate/mcp_http.go` — Retain agent identity across multi-tenant HTTP requests in session storage.
- `internal/gate/forwarder.go` — Remove `SendLogs` from `KeepForwarder` interface and client implementation.
- `internal/gate/decision_logger.go` — Remove obsolete Gate-side decision log shipping buffer and worker.
- `internal/keep/config.go` — Update Keep configuration to parse and validate `mcp_activity_log`.
- `internal/keep/server.go` — Remove `POST /log` endpoint, wire `ActivityLogger` around `CallTool` and PDP evaluations, and emit correlated request and response/synthetic denial records.
- `internal/keep/activitylog/` (new package) — Asynchronous buffered worker, `ActivitySink` interface, rotating file sink using `lumberjack.v2`, payload truncation logic, and graceful flush/shutdown.
- `internal/keep/decisionlog.go` & `internal/keep/decisionlog_test.go` — Remove obsolete HTTP decision logger.

---

## Approaches Considered

### Approach 1: Decoupled Async Worker with Pluggable Sink & Lumberjack Rotation (Selected)
- **Description**: Keep dispatches structured audit events through an in-memory buffered channel to an asynchronous background worker. The worker handles payload truncation, marshals records into single-line JSON, and writes to an `ActivitySink` interface. The primary file sink wraps `gopkg.in/natefinch/lumberjack.v2` for size-triggered rotation, max file age, max backup counts, and gzip compression. A stdout sink is available for containerized cloud deployments.
- **Pros**:
  - Completely decouples MCP tool execution latency from local disk I/O.
  - Safe under heavy concurrent tool traffic (non-blocking drops or high-capacity buffering).
  - Pluggable interface allows future SIEM/streaming sinks (e.g. S3, Kafka, syslog) without modifying core request handlers.
  - Battle-tested rotation logic via lumberjack avoids reinventing log rotation wheel.
- **Cons**: Requires explicit lifecycle management (graceful draining and flushing on shutdown).

### Approach 2: Synchronous Mutex-Guarded File Writer
- **Description**: Request handlers directly serialize and write log lines to an `os.File` protected by a `sync.Mutex` synchronously before returning responses.
- **Pros**: Simplest concurrency model; zero risk of memory buffering issues; immediate durability before responding.
- **Cons**: Disk write stalls or slow storage directly impact tool execution latency; mutex contention on high concurrency.

### Approach 3: Dedicated `log/slog` Subsystem
- **Description**: Configure a separate `slog.Logger` pointing to a rotating file writer, formatting activity events as structured slog attributes.
- **Pros**: Reuses Go standard library components.
- **Cons**: `slog.JSONHandler` escapes nested arbitrary JSON maps/arrays (like MCP tool arguments and response structures), forcing messy double-unmarshaling or raw string wrappers; couples SIEM audit schemas to standard logging conventions.

---

## Detailed Design

### 1. Agent Identity Discovery & Protocol Propagation
Standard MCP clients provide identity information during session initialization:
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "initialize",
  "params": {
    "protocolVersion": "2024-11-05",
    "clientInfo": {
      "name": "claude-code",
      "version": "1.0.0"
    }
  }
}
```

#### Shared Types (`internal/shared/types.go`)
Define `AgentInfo` and update `EnrichedMCPRequest`:
```go
type AgentInfo struct {
    Name    string `json:"name"`
    Version string `json:"version"`
}

type EnrichedMCPRequest struct {
    APIVersion       string            `json:"api_version,omitempty"`
    ServerName       string            `json:"server_name"`
    ToolName         string            `json:"tool_name"`
    Arguments        map[string]any    `json:"arguments"`
    UserIdentity     UserIdentity      `json:"user_identity"`
    Agent            AgentInfo         `json:"agent"` // Discovered agent metadata
    EscalationTokens []EscalationToken `json:"escalation_tokens"`
    SessionID        string            `json:"session_id"`
    TraceID          string            `json:"trace_id"`
    ClientHeaders    map[string][]string `json:"client_headers,omitempty"`
}
```

#### Gate Server Middleware & Session Storage
1. **Extraction**: Register a receiving middleware on `Gate.server` (`mcp.AddReceivingMiddleware`). When `method == "initialize"`, parse `req.Params.ClientInfo`. If `clientInfo` is missing or empty, default `Name` and `Version` to `"unknown"`.
2. **Session Storage Interface Extensions (`internal/gate/session_store.go`)**:
   Add explicit agent metadata methods to `SessionStore`, implemented by both `MemorySessionStore` and `RedisSessionStore`:
   ```go
   type SessionStore interface {
       SaveSession(ctx context.Context, sessionID, userID string, state []byte) error
       SaveSessionIfAbsent(ctx context.Context, sessionID, userID string, state []byte) (bool, error)
       GetSession(ctx context.Context, sessionID string) (state []byte, userID string, err error)
       DeleteSession(ctx context.Context, sessionID string) error

       // Agent metadata methods:
       SaveAgentInfo(ctx context.Context, sessionID string, agent shared.AgentInfo) error
       GetAgentInfo(ctx context.Context, sessionID string) (shared.AgentInfo, error)
   }
   ```
   - **Isolation from Credential Fingerprints**: In `MultiTenantProvider.Authenticate`, `state []byte` stores the raw SHA-256 hash of the caller's credential token, and Gate performs an exact byte comparison (`bytes.Equal(st, fp)`) on every request to detect token hijacking. `AgentInfo` is stored in a completely distinct field/key (`s.agent` in memory; a dedicated field or key in Redis) and is never serialized into or combined with `state []byte`. This guarantees that saving or updating agent metadata will never modify, corrupt, or invalidate the credential fingerprint.
3. **Multi-Tenant Session ID Association & Response Interception**:
   - *Problem*: In multi-tenant HTTP mode, the client does not send an `Mcp-Session-Id` header during the initial `initialize` request. The MCP Go SDK assigns its own session ID internally and writes it to the response header `Mcp-Session-Id: <sdk-session-id>`. Any temporary internal ID minted by `MultiTenantProvider.Authenticate` before SDK execution is never returned to or seen by the client; all subsequent requests (e.g. `tools/call`) arrive bearing the SDK's returned ID.
   - *Solution*:
     1. During `initialize`, the receiving middleware extracts `clientInfo` and attaches it to a request-scoped context pointer (`agentInitCapture`).
     2. `MCPHTTPHandler.ServeHTTP` wraps `http.ResponseWriter` with an interceptor that captures the outgoing `Mcp-Session-Id` response header set by the SDK.
     3. Once `h.sdkHandler.ServeHTTP` completes, `MCPHTTPHandler` retrieves the SDK's actual returned session ID from the interceptor.
     4. `MCPHTTPHandler` immediately saves `agentInitCapture` into `SessionStore` under the SDK's returned session ID via `p.sessions.SaveAgentInfo(ctx, sdkSessionID, agentInfo)`.
4. **Single-Tenant Storage**:
   - Store `AgentInfo` in `Gate` state (thread-safe, set once per process lifecycle during stdio `initialize`).
5. **Propagation**: In `Gate.handleToolCall`, extract the session's `AgentInfo` (from `Gate` state in single-tenant; via `sessionStore.GetAgentInfo(ctx, sessionID)` in multi-tenant) and populate `req.Agent` on `EnrichedMCPRequest`. If not found, default to `unknown:unknown`.

---

### 2. Retirement of Legacy `decision_log`
The previous HTTP-forwarding decision log facility is decommissioned:
1. **Gate**:
   - Delete `internal/gate/decision_logger.go`.
   - Remove `logger DecisionLogger` field from `Gate` struct.
   - Remove `SendLogs` from `KeepForwarder` interface in `internal/gate/server.go` and `internal/gate/forwarder.go`.
   - Remove background log flusher from `Gate.Run`.
2. **Keep**:
   - Delete `internal/keep/decisionlog.go` and `internal/keep/decisionlog_test.go`.
   - Remove `mux.HandleFunc("POST /log", s.handleLog)` and handler from `internal/keep/server.go`.
   - Remove `decisionLog *DecisionLogger` field from Keep's `Server`.
   - Remove `DecisionLogConfig` from `KeepConfig`. If an older configuration file includes `decision_log`, Keep will log an informational warning noting that `decision_log` is deprecated and ignored in favor of `mcp_activity_log`.

---

### 3. MCP Activity Log Engine (`internal/keep/activitylog/`)

#### Configuration Schema (`keep.yaml`)
```yaml
mcp_activity_log:
  enabled: true
  file: "/var/log/portcullis/mcp-activity.log" # Path to log file; set explicitly to "stdout" for stdout (default: "/var/log/portcullis/mcp-activity.log")
  max_size_mb: 100                             # Max megabytes before rotation (default: 100)
  max_backups: 10                              # Retained rotated files (default: 10)
  max_age_days: 30                             # Max days before deletion (default: 30)
  compress: false                              # Gzip compress rotated files (default: false)
  include_pdp_decision: false                  # Attach pdp decision/reason to request record (default: false)
  truncate_payloads: false                     # Enable truncation of arguments/results (default: false)
  max_payload_bytes: 4096                      # Max byte threshold when truncation enabled (default: 4096)
  buffer_size: 10000                           # In-memory queue capacity (default: 10000)
```

##### Configuration Defaults & Presence-Aware Booleans
To distinguish omitted booleans from explicit boolean values, `Compress` and `IncludePDPDecision` use pointer booleans (`*bool`) with helper methods that default to `false`:
- **`compress: false` (default)**: Avoids file-watcher and lock contention with local SIEM collectors (e.g. Filebeat, Splunk forwarder, Vector) that tail active and newly rotated files, avoids redundant double-compression across the network, and eliminates background CPU spikes during log rotation.
- **`include_pdp_decision: false` (default)**: Avoids duplicating policy decisions in downstream SIEM storage when the PDP already maintains its own dedicated, authoritative decision logging pipeline, maintaining strict separation of concerns for the MCP tool flight recorder.

```go
type MCPActivityLogConfig struct {
    Enabled            bool   `yaml:"enabled"`
    File               string `yaml:"file"`
    MaxSizeMB          int    `yaml:"max_size_mb"`
    MaxBackups         int    `yaml:"max_backups"`
    MaxAgeDays         int    `yaml:"max_age_days"`
    Compress           *bool  `yaml:"compress"`             // nil = omitted (default: false)
    IncludePDPDecision *bool  `yaml:"include_pdp_decision"` // nil = omitted (default: false)
    TruncatePayloads   bool   `yaml:"truncate_payloads"`
    MaxPayloadBytes    int    `yaml:"max_payload_bytes"`
    BufferSize         int    `yaml:"buffer_size"`
}

func (c *MCPActivityLogConfig) IsCompressed() bool {
    if c.Compress == nil {
        return false
    }
    return *c.Compress
}

func (c *MCPActivityLogConfig) ShouldIncludePDPDecision() bool {
    if c.IncludePDPDecision == nil {
        return false
    }
    return *c.IncludePDPDecision
}
```

| Field | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `enabled` | `bool` | `false` | Master switch for MCP activity logging |
| `file` | `string` | `"/var/log/portcullis/mcp-activity.log"` | Log file path with automated rotation. If empty, defaults to this path. Set explicitly to `"stdout"` to stream to stdout without rotation |
| `max_size_mb` | `int` | `100` | Max file size in megabytes before rotation |
| `max_backups` | `int` | `10` | Maximum number of retained rotated files |
| `max_age_days` | `int` | `30` | Maximum days to retain rotated files |
| `compress` | `*bool` | `false` | Whether rotated log files are gzip compressed (nil = default false; preserves explicit true) |
| `include_pdp_decision` | `*bool` | `false` | Whether to include PDP evaluation verdict in the request record (nil = default false; preserves explicit true) |
| `truncate_payloads` | `bool` | `false` | Whether to truncate large arguments and results |
| `max_payload_bytes` | `int` | `4096` | Max byte threshold for payload truncation (used when `truncate_payloads: true`) |
| `buffer_size` | `int` | `10000` | Fixed capacity of the in-memory log event queue |

#### Event Format (JSON-lines)
Under normal execution, each tool invocation emits two correlated records sharing `trace_id` and `session_id`. Special handling applies to failure scenarios before or during policy evaluation.

##### 1. Malformed Request Event (`event: "mcp_malformed_request"`)
If an incoming request to Keep's `/call` endpoint fails JSON unmarshaling, violates schema limits, has an invalid API version, or contains illegal client headers before PDP evaluation, Keep captures this as a security event (e.g. in case a subverted agent is probing for parser vulnerabilities):
```json
{
  "timestamp": "2026-11-03T20:15:30.050000Z",
  "event": "mcp_malformed_request",
  "remote_addr": "10.0.4.15:54322",
  "trace_id": "4bf92f3577b34da6a3ce929d0e0e4736",
  "error": "decode tool arguments: unexpected end of JSON input",
  "raw_preview": "{\"server_name\": \"database-mcp\", \"arguments\": {\"query\": \"SELECT..."
}
```
- **Bound on `raw_preview`**: To prevent memory exhaustion and SIEM log bloat if an adversary streams large bodies (e.g. 10MB of garbage), `raw_preview` is strictly capped at `max_payload_bytes` (default: 4096 bytes), regardless of whether `truncate_payloads` is enabled.
- **Body Preservation via Capped Tee Reader**: In `handleCall`, decoding directly from `r.Body` consumes bytes that cannot be re-read after a decode failure. To capture `raw_preview` without pre-buffering or consuming the stream ahead of the decoder:
  - Keep wraps `r.Body` with a `cappedTeeReader`: an `io.Reader` that streams bytes through to `json.NewDecoder(tee)` while simultaneously recording the first `max_payload_bytes` into an internal bounded buffer.
  - Once the buffer reaches `max_payload_bytes`, the tee stops recording but continues passing subsequent stream bytes through to the JSON decoder unimpeded.
  - If decoding or subsequent pre-PDP schema validation fails, the recorded buffer contains the initial bytes of the exact input stream without requiring a secondary read or allocating memory for the entire payload.
- **UTF-8 Alignment**: If the recorded byte slice ends mid-rune, it steps backwards up to 3 bytes to the nearest complete UTF-8 rune boundary so `raw_preview` is always valid UTF-8.
*Note: No `mcp_response` record is emitted for malformed requests; Keep immediately responds with an HTTP 400 Bad Request.*

##### 2. Request Event (`event: "mcp_request"`)
Emitted immediately for all successfully parsed tool calls, including those rejected at pre-PDP security boundaries (identity normalization failure and hidden tool name rejection) as well as those evaluated by the PDP:
- **Network Provenance (`remote_addr`)**: Every request, response, and malformed event includes `remote_addr` (`r.RemoteAddr`), providing consistent network-layer provenance for lateral movement detection, IP threat intelligence, and distributed SIEM correlation.
- **Identity Normalization Failure**: If a well-formed request carries an invalid, expired, or untrusted user identity token, Keep logs an `mcp_request` record (with `user_id` populated from `rawReq.UserIdentity.UserID` if present or `"unauthenticated"`, and `pdp_decision: "auth_failed"` if `include_pdp_decision: true`).
- **Hidden Tool Name Rejection**: If an agent attempts to call the unaliased real name of a hidden tool (an evasion attempt), Keep logs an `mcp_request` record (with `pdp_decision: "deny"` and `pdp_reason: "unknown tool: hidden tool alias rejection"` if `include_pdp_decision: true`).
- **PDP Down / Infrastructure Failure**: If the PDP is unreachable, times out, or fails with an internal error, an `mcp_request` record is emitted (with `pdp_decision: "error"` and `pdp_reason: err.Error()` if `include_pdp_decision: true`, or with those fields omitted if `include_pdp_decision: false`). Keep returns an HTTP 503 Service Unavailable (`shared.ErrPDPUnavailable`).
- **Standard Format (`include_pdp_decision: true`)**:
```json
{
  "timestamp": "2026-11-03T20:15:30.123456Z",
  "event": "mcp_request",
  "remote_addr": "10.0.4.15:54322",
  "session_id": "sess-4a8b-91c2",
  "trace_id": "4bf92f3577b34da6a3ce929d0e0e4736",
  "user_id": "alice@corp.internal",
  "agent": {
    "name": "claude-code",
    "version": "1.0.0"
  },
  "server_name": "database-mcp",
  "tool_name": "query_customers",
  "arguments": {
    "query": "SELECT id, name FROM customers WHERE region = 'US'"
  },
  "pdp_decision": "allow",
  "pdp_reason": ""
}
```
- **Behavior with `include_pdp_decision: false`**:
  - *Rationale*: In many enterprise architectures, the PDP (e.g., OPA, Permit.io, Cedar) already maintains its own dedicated, authoritative decision log pipeline. Including PDP decisions in Keep's activity log represents duplicate log volume and redundant SIEM storage. Administrators can set `include_pdp_decision: false` to streamline the log to pure MCP tool interaction telemetry.
  - *Omission Rule*: When `include_pdp_decision` is `false`, the `pdp_decision` and `pdp_reason` fields are **omitted entirely** from the JSON output (using `omitempty` and nil pointer / empty value suppression), not output as zeroed or empty strings:
```json
{
  "timestamp": "2026-11-03T20:15:30.123456Z",
  "event": "mcp_request",
  "remote_addr": "10.0.4.15:54322",
  "session_id": "sess-4a8b-91c2",
  "trace_id": "4bf92f3577b34da6a3ce929d0e0e4736",
  "user_id": "alice@corp.internal",
  "agent": {
    "name": "claude-code",
    "version": "1.0.0"
  },
  "server_name": "database-mcp",
  "tool_name": "query_customers",
  "arguments": {
    "query": "SELECT id, name FROM customers WHERE region = 'US'"
  }
}
```

##### 3. Response Event (`event: "mcp_response"`)
- **Response Status Classification Rules**:
  1. `status: "success"`: `router.CallTool` returned `err == nil` AND `result.IsError == false`. `result` contains backend output; `error` is omitted.
  2. `status: "error"` (Tool-Level Failure): `router.CallTool` returned `err == nil` BUT `result.IsError == true` (the standard MCP pattern for tool-level errors like database query errors or file not found). `result` is **retained** with full structured content (truncated if truncation enabled), and `error` contains `"tool returned error"` (or extracted error text from content blocks).
  3. `status: "error"` (Backend Infrastructure Failure): `router.CallTool` returned `err != nil` (e.g. timeout, process crash, network failure). `result` is `nil`, and `error` contains `"backend tool call failed: " + err.Error()`.
  4. `status: "denied"`, `"escalation_pending"`, `"error"`: Pre-PDP rejections (identity normalization failure, hidden tool rejection) or PDP policy outcomes.

- **Successful Execution (`result.IsError == false`)**:
```json
{
  "timestamp": "2026-11-03T20:15:30.245100Z",
  "event": "mcp_response",
  "remote_addr": "10.0.4.15:54322",
  "session_id": "sess-4a8b-91c2",
  "trace_id": "4bf92f3577b34da6a3ce929d0e0e4736",
  "user_id": "alice@corp.internal",
  "agent": {
    "name": "claude-code",
    "version": "1.0.0"
  },
  "server_name": "database-mcp",
  "tool_name": "query_customers",
  "duration_ms": 121,
  "status": "success",
  "result": {
    "content": [
      {
        "type": "text",
        "text": "[{\"id\": 1, \"name\": \"Acme Corp\"}]"
      }
    ]
  }
}
```

- **Tool-Level Error Execution (`result.IsError == true`)**:
```json
{
  "timestamp": "2026-11-03T20:15:30.210000Z",
  "event": "mcp_response",
  "remote_addr": "10.0.4.15:54322",
  "session_id": "sess-4a8b-91c2",
  "trace_id": "4bf92f3577b34da6a3ce929d0e0e4736",
  "user_id": "alice@corp.internal",
  "agent": {
    "name": "claude-code",
    "version": "1.0.0"
  },
  "server_name": "database-mcp",
  "tool_name": "query_customers",
  "duration_ms": 45,
  "status": "error",
  "error": "tool returned error: table 'customers' does not exist",
  "result": {
    "isError": true,
    "content": [
      {
        "type": "text",
        "text": "table 'customers' does not exist"
      }
    ]
  }
}
```

- **Synthetic Denial / Pre-PDP Security Rejection / Escalation / Error**:
Whenever a well-formed request is halted before backend completion—whether due to identity normalization failure, hidden tool rejection, PDP denial, escalation pending, PDP infrastructure failure, or backend MCP execution failure—a synthetic response record is emitted immediately. **Even if `include_pdp_decision: false`, this synthetic response record is always emitted** so that every well-formed tool request is paired with a terminal response record:
  - *Identity Normalization Failure*:
    ```json
    {
      "timestamp": "2026-11-03T20:15:30.080000Z",
      "event": "mcp_response",
      "remote_addr": "10.0.4.15:54322",
      "session_id": "sess-4a8b-91c2",
      "trace_id": "4bf92f3577b34da6a3ce929d0e0e4736",
      "user_id": "unauthenticated",
      "agent": {
        "name": "claude-code",
        "version": "1.0.0"
      },
      "server_name": "database-mcp",
      "tool_name": "query_customers",
      "duration_ms": 2,
      "status": "error",
      "error": "identity normalization failed: token signature invalid"
    }
    ```
  - *Hidden Tool Rejection*:
    ```json
    {
      "timestamp": "2026-11-03T20:15:30.090000Z",
      "event": "mcp_response",
      "remote_addr": "10.0.4.15:54322",
      "session_id": "sess-4a8b-91c2",
      "trace_id": "4bf92f3577b34da6a3ce929d0e0e4736",
      "user_id": "alice@corp.internal",
      "agent": {
        "name": "claude-code",
        "version": "1.0.0"
      },
      "server_name": "database-mcp",
      "tool_name": "raw_db_exec",
      "duration_ms": 1,
      "status": "denied",
      "error": "unknown tool"
    }
    ```
  - *Escalation Pending*:
    ```json
    {
      "timestamp": "2026-11-03T20:15:30.130000Z",
      "event": "mcp_response",
      "remote_addr": "10.0.4.15:54322",
      "session_id": "sess-4a8b-91c2",
      "trace_id": "4bf92f3577b34da6a3ce929d0e0e4736",
      "user_id": "alice@corp.internal",
      "agent": {
        "name": "claude-code",
        "version": "1.0.0"
      },
      "server_name": "database-mcp",
      "tool_name": "drop_table",
      "duration_ms": 4,
      "status": "escalation_pending",
      "escalation_jti": "jti-9f8e-1234-abcd",
      "workflow_reference": "TICKET-4481"
    }
    ```
  - *Policy Denial*:
    ```json
    {
      "timestamp": "2026-11-03T20:15:30.140000Z",
      "event": "mcp_response",
      "remote_addr": "10.0.4.15:54322",
      "session_id": "sess-4a8b-91c2",
      "trace_id": "4bf92f3577b34da6a3ce929d0e0e4736",
      "user_id": "alice@corp.internal",
      "agent": {
        "name": "claude-code",
        "version": "1.0.0"
      },
      "server_name": "database-mcp",
      "tool_name": "drop_table",
      "duration_ms": 5,
      "status": "denied",
      "error": "production database write prohibited by policy"
    }
    ```
  - *PDP Infrastructure Failure*:
    ```json
    {
      "timestamp": "2026-11-03T20:15:30.140000Z",
      "event": "mcp_response",
      "remote_addr": "10.0.4.15:54322",
      "session_id": "sess-4a8b-91c2",
      "trace_id": "4bf92f3577b34da6a3ce929d0e0e4736",
      "user_id": "alice@corp.internal",
      "agent": {
        "name": "claude-code",
        "version": "1.0.0"
      },
      "server_name": "database-mcp",
      "tool_name": "drop_table",
      "duration_ms": 5,
      "status": "error",
      "error": "pdp evaluation failed: context deadline exceeded"
    }
    ```

- **Multi-Step Escalation Lifecycle & Trace Correlation**:
When an unprivileged tool call requires human escalation, Keep emits an `mcp_request` followed by a synthetic `mcp_response` with `status: "escalation_pending"`. Once the human approves in Guard, the agent retries the tool invocation presenting the approved escalation token.
  - **Trace ID Generation & Propagation**: In the absence of an external distributed trace context (such as a W3C `traceparent` header supplied by an orchestrator in multi-tenant HTTP mode), Gate generates a fresh UUID `trace_id` for every incoming tool invocation (`telemetry.TraceIDFromContext(ctx)` falling back to `uuid.New().String()`). Consequently, the initial unprivileged request and the subsequent approved retry will typically have **distinct `trace_id` values** (e.g., `trace_id_1` and `trace_id_2`).
  - **Unbroken Escalation Linkage via `escalation_jti`**:
    - **Initial Attempt**: When the PDP requires escalation, Keep's signer creates the pending JWT with a unique JWT ID (`jti`). Keep attaches this identifier (`escalation_jti: "jti-..."`) and any workflow reference (`workflow_reference: "..."`) directly to the initial synthetic `mcp_response` record (`status: "escalation_pending"`), cementing the JTI in the initial audit record.
    - **Approved Retry**: When the agent retries the tool call with the approved escalation token attached, Keep extracts the token's JTI and records it in the retry's `mcp_request` entry (`escalation_jti: "jti-..."`).
    - **End-to-End Correlation**: Querying by `escalation_jti` provides an unbroken forensic chain across both distinct trace IDs and Guard server logs:
      1. Initial `mcp_request` and `mcp_response` (`status: "escalation_pending"`, `escalation_jti`) under `trace_id_1`.
      2. Guard / Keep server log for `lazy_claim` (`jti`) under `trace_id_2`.
      3. Retried `mcp_request` (`escalation_jti`) and final `mcp_response` (`status: "success"`) under `trace_id_2`.
  - **Intra-Call Correlation (via `trace_id`)**:
    - `trace_id_1` strictly correlates the initial `mcp_request` with its synthetic `mcp_response` (`status: "escalation_pending"`).
    - `trace_id_2` strictly correlates the retry `mcp_request`, the Keep `lazy_claim` structured server log, and the final `mcp_response` (`status: "success"` or backend error).

#### Payload Truncation & Pre-Enqueue Sizing Rules
To prevent memory exhaustion in the buffered queue, **truncation is evaluated and applied before an entry is placed on the channel**, not inside the background worker:
- When `LogRequest` or `LogResponse` is called, `arguments` and `result` payloads are serialized to JSON bytes (`rawJSON := json.Marshal(...)`).
- If `truncate_payloads` is `true` and `len(rawJSON) > max_payload_bytes`, the payload field on the queued entry is immediately replaced with a truncation metadata envelope before enqueue:
  ```json
  {
    "_truncated": true,
    "_bytes": 65536,
    "_preview": "{\"content\":[{\"type\":\"text\",\"text\":\"First ~4096 bytes of valid UTF-8 text..."
  }
  ```
- **Field Definitions & Boundary Handling**:
  - `_truncated` (`bool`): Always `true` when truncation occurred.
  - `_bytes` (`int`): The exact total byte length of the original serialized JSON payload before truncation (e.g., `65536` for a 64KB response).
  - `_preview` (`string`): A UTF-8 string scalar containing the prefix of the payload up to `max_payload_bytes`.
  - **UTF-8 Boundary Alignment**: Slicing raw bytes at an arbitrary offset can bisect a multi-byte UTF-8 code point (runes range from 1 to 4 bytes). To prevent emitting invalid UTF-8 sequences or corrupted replacement characters (`\uFFFD`), truncation inspects the boundary: if `rawJSON[:max_payload_bytes]` ends mid-rune, the slice steps backwards by up to 3 bytes until ending on a complete, valid UTF-8 rune boundary. The resulting validated slice is converted to string for the `_preview` field.

#### Qualified Completeness & Forensic Memory Trade-offs
- **Queue Bounds are Entry-Count Based, Not Absolute Byte Bounds**: The `buffer_size` setting (default: 10,000) caps the *number of queued events*, not total heap memory.
- **Full Forensic Fidelity when Truncation is Disabled (`truncate_payloads: false`)**:
  - When `truncate_payloads` is `false`, **no truncation is performed on either request arguments or backend tool results**.
  - *Architectural Rationale*: Portcullis sits as the authoritative security boundary in the agent ecosystem. In a post-incident forensic investigation of a compromised or rogue AI agent (e.g., detecting unauthorized data exfiltration, secret leakage, or unauthorized API calls), security teams require the exact, unadulterated payload to understand what data left the boundary.
  - *Memory Impact*: In this mode, queue heap memory is variable and directly proportional to the size of tool arguments and backend responses. Operators who prioritize complete forensic visibility accept this memory trade-off.
- **Predictable Memory Footprint with Truncation Enabled (`truncate_payloads: true`)**:
  - When memory predictability is required (e.g. tightly constrained container environments), setting `truncate_payloads: true` evaluates and enforces `max_payload_bytes` on both arguments and results before enqueue.
  - The maximum theoretical queue memory is strictly capped at approximately:
    $$\text{Max Queue Heap} \approx \text{buffer\_size} \times (\text{max\_payload\_bytes} + \text{event\_metadata\_overhead})$$
    With default settings (`buffer_size: 10000`, `max_payload_bytes: 4096`), queue memory is bounded to $\approx 45 \text{ MB}$.
- **Non-Blocking Hot Path (Drop on Full)**: If the channel is full (e.g., during severe disk I/O latency, backup locks, or sudden request surges), excess events are immediately dropped via non-blocking send. Producers never block, sleep, or allocate fallback memory buffers.
- **Traceable Drop Metrics**: Dropped records atomically increment `droppedCount` and are periodically logged to slog as warnings and exposed via service diagnostics so operators are alerted to buffer pressure.
- **Sink Write Failures (Lumberjack / Disk Errors)**: If the underlying sink (such as lumberjack or disk I/O) returns an error during a write (e.g., disk full, write permissions revoked, or hardware fault):
  - The error is logged immediately to `slog.Error("activity log sink write failed", "error", err)`.
  - The affected record is dropped, and an atomic `sinkErrorCount` is incremented.
  - The background worker continues processing remaining items without panicking, crashing, or blocking Keep proxy traffic.
- **Qualified Durability**: Delivery to disk is guaranteed for admitted events under normal operation with responsive storage. Under catastrophic failure (OOM, hardware power loss, ungraceful SIGKILL, or disk failure), unwritten buffered events may be lost.

#### Concurrency & Lock-Free Lifecycle
- `ActivityLogger` manages a fixed-capacity buffered channel (`al.ch`) and an atomic status flag (`al.closed atomic.Bool`).
- **Disabled State & Nil Safety**:
  - `New(cfg, sink)` always returns a valid, non-nil `*ActivityLogger`. If `cfg.Enabled` is `false`, `New` constructs a lightweight disabled logger: no background worker goroutine is spawned, no file descriptors are opened, and no channel is allocated.
  - All public methods (`LogRequest`, `LogResponse`, `LogMalformedRequest`, `Shutdown`, `Stats`) are **strictly nil-safe**:
    ```go
    func (al *ActivityLogger) LogRequest(req *RequestEntry) {
        if al == nil || !al.cfg.Enabled || al.closed.Load() {
            return
        }
        // ...
    }
    ```
  - In `handleCall`, Keep checks `s.activityLog.Enabled()` before wrapping `r.Body` with `cappedTeeReader`. When activity logging is disabled (the default), `r.Body` passes directly to `json.NewDecoder(r.Body)` with zero allocation and zero overhead.
- **Hot-Path Enqueue (`LogRequest` / `LogResponse`)**:
  - Entirely lock-free with zero mutex contention:
    ```go
    if al == nil || !al.cfg.Enabled || al.closed.Load() {
        return
    }
    select {
    case al.ch <- entry:
    default:
        atomic.AddInt64(&al.droppedCount, 1)
    }
    ```
  - **Panic-Free Design**: `al.ch` is **never closed**. Because the channel remains open for the lifetime of the process, concurrent or straggling producers can NEVER panic on send. Once `al.closed` is set, calls simply drop and return.
- **Idempotent Shutdown Sequence (`Shutdown(ctx context.Context) error`)**:
  - Wrapped in `sync.Once` to ensure safe, idempotent execution across multiple callers or signal handlers.
  - **Step 1 (Signal Stop)**: Atomically set `al.closed.Store(true)`. All subsequent tool log calls exit immediately.
  - **Step 2 (Signal Worker & Drain)**: Close a separate control channel `al.stopWorker chan struct{}`. The background worker intercepts `stopWorker` and performs a non-blocking drain of whatever entries are currently in `al.ch`, writing them to the sink.
  - **Step 3 (Bounded Wait)**: The shutdown caller waits for `al.workerDone` with a timeout governed by `ctx.Done()`. If the context expires before the buffer can be fully written to disk, remaining queued items are discarded to prevent process hang.
  - **Step 4 (Sink Close)**: Flush and close the underlying `ActivitySink` (e.g. closing the file descriptor).
  - Return `ctx.Err()` if shutdown timed out, or any sink closure error.

---

## Verification Plan

### Automated Tests
1. **Gate MCP Handshake Test**:
   - Verify `mcp.InitializeRequest` with `clientInfo` properly sets `AgentInfo` in Gate session.
   - Verify tool calls carry `req.Agent` in `EnrichedMCPRequest`.
   - Verify missing `clientInfo` gracefully defaults to `"unknown"`.
2. **Keep Activity Logger Unit Tests**:
   - Verify `LogRequest` and `LogResponse` emit valid single-line JSON with correct timestamps and fields.
   - Verify payload truncation correctly replaces oversized arguments and results while preserving metadata.
   - Verify synthetic denial emits matching `mcp_response` with status `"denied"` and error details.
   - **Shutdown Race & Idempotency Test**: Run concurrent worker goroutines hammering `LogRequest` and `LogResponse` while `Shutdown` is invoked from multiple goroutines simultaneously; verify zero panics, clean admission rejection after shutdown, and all admitted records drained to the sink.
   - Verify graceful shutdown flushes all buffered entries before returning.
3. **Rotation & Lumberjack Integration Test**:
   - Configure a small `max_size_mb` (or small byte test target) and verify file rotation occurs without corrupting JSON lines.
4. **End-to-End Flow Test**:
   - Execute a tool call through Gate -> Keep -> Mock Backend.
   - Assert both `mcp_request` and `mcp_response` lines appear in the configured activity log file with matching `trace_id` and valid `agent` metadata.
