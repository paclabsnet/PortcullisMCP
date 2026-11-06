# Remote Activity Log Sinks Design (HTTPS & OTLP)

## Objective
Provide remote, network-based audit log export capabilities for Keep's `mcp_activity_log` by implementing an **HTTPS Batch Sink** and an **OpenTelemetry (OTLP/HTTP) Log Sink**. This allows organizations with strict data-at-rest privacy policies (e.g., HIPAA, SOC 2, GDPR) to stream agent activity directly into centralized SIEMs (such as Splunk HEC raw endpoints, OpenTelemetry Collectors, or corporate log pipeline ingest gateways) from process memory over TLS, completely eliminating local disk storage.

---

## Goals & Non-Goals

### Goals
- **Zero Local Disk Footprint**: When `sink: "http"` or `sink: "otlp"` is configured, no log files are created, opened, or rotated on the host filesystem.
- **HTTPS Batch Sink (`http`)**: Stream newline-delimited JSON-lines (NDJSON) batches directly to HTTP ingest gateways and endpoints that accept raw JSON-lines (such as Splunk HEC raw mode, Logstash/Vector/Fluentd HTTP listeners, or custom security webhooks).
- **OpenTelemetry Log Sink (`otlp`)**: Stream structured log records formatted according to the standard OTLP/HTTP `/v1/logs` specification to internal OpenTelemetry Collectors (which handle downstream routing to backends like Datadog, Elastic, Splunk, or cloud SIEMs).
- **Configurable Batching & Timing**: Configurable `batch_size`, `flush_interval_ms`, `timeout_ms`, `max_retries`, and `retry_backoff_ms` with sensible defaults.
- **Best-Effort & Bounded Memory**: Proxy tool execution is never blocked or throttled by remote SIEM downtime; failed batches make quick retries before non-blocking drop with atomic metric tracking.
- **TLS & Secret Resolution**: Support enterprise CA certificates (`ca_cert_file`), insecure dev flags, and dynamic secret resolution (`envvar://`, `vault://`) in custom authentication headers.

### Non-Goals
- **Local Disk Spooling / Fallback (Zero-Disk Mandate)**: Under no circumstances does `mcp_activity_log` automatically fall back to local file logging if a remote sink encounters a misconfiguration (e.g., bad URL, invalid TLS cert) or network outage. Silently writing raw prompts, arguments, or tool outputs to host storage would violate the organization's data-at-rest compliance mandate (e.g. HIPAA, SOC 2, GDPR). If a remote sink fails or is misconfigured, Keep logs the operational failure to its standard process log (`slog`), but MCP request/response payloads are never redirected to a local file.
- **Proprietary Vendor Protocols / Action-Line Bulk Wrappers**: The `http` sink does not construct specialized metadata-interleaved wrappers such as Elasticsearch / OpenSearch `_bulk` action lines. Organizations routing directly to Elasticsearch or OpenSearch without Logstash/Vector should target an OpenTelemetry Collector via the `otlp` sink. (Standard JSON-array ingestion endpoints such as Datadog Logs API `/api/v2/logs` and OPA harvesters are directly supported via `encoding: "json_array"`).
- **HTTP 429 Rate Limiting & 408 Retries**: All HTTP 4xx responses (including 429 Too Many Requests and 408 Request Timeout) are treated uniformly as non-retryable client rejections (the batch is logged and dropped immediately without retries). Complex `Retry-After` header parsing, adaptive backoff pacing, and client-side rate limiting are intentionally excluded and reserved for a future commercial/enterprise edition of Portcullis.

---

## Architecture & Sink Interface

The core logging engine in `internal/keep/activitylog/` utilizes the existing `ActivitySink` interface:
```go
type ActivitySink interface {
    Write(line []byte) error
    Close() error
}
```

When Keep initializes with remote sinks:
1. `ActivityLogger` continues enqueueing formatted single-line JSON records over its lock-free channel.
2. The background worker passes entries to the selected `ActivitySink`.
3. For network sinks, entries accumulate in an in-memory batch buffer until either `batch_size` is reached or `flush_interval_ms` elapses.
4. The batch is dispatched via an HTTP `POST` over TLS.
5. On shutdown, `Close()` flushes any remaining buffered records within the shutdown timeout.

---

## Configuration Schema (`keep.yaml`)

All core activity logging policies (queue sizing, payload truncation, and PDP decision inclusion) are declared at the **top level** and apply universally regardless of which sink is active:

```yaml
mcp_activity_log:
  # ============================================================================
  # Top-Level Policy (Applies universally across all sinks)
  # ============================================================================
  enabled: true
  sink: "file"                  # Target sink: "file" (default) | "stdout" | "http" | "otlp"
  buffer_size: 10000            # In-memory queue capacity before non-blocking drop (default: 10000)
  truncate_payloads: false      # Whether to truncate arguments & results (default: false)
  max_payload_bytes: 4096       # Byte ceiling when truncation enabled (default: 4096)
  include_pdp_decision: false   # Whether to include PDP verdict in request record (default: false)

  # ============================================================================
  # Local Rotating File Sink Configuration (Active when sink: "file")
  # ============================================================================
  file: "/var/log/portcullis/mcp-activity.log"
  max_size_mb: 100              # Max megabytes before rotation (default: 100)
  max_backups: 10               # Retained rotated files (default: 10)
  max_age_days: 30              # Max days before deletion (default: 30)
  compress: false               # Gzip compress rotated files (default: false)

  # ============================================================================
  # HTTPS Batch Sink Configuration (Active when sink: "http")
  # ============================================================================
  http:
    url: "https://splunk-hec.corp.internal:8088/services/collector/raw"
    encoding: "ndjson"          # Batch wire encoding: "ndjson" (default) | "json_array"
    auth:
      type: "splunk"            # Auth scheme: "splunk" ("Splunk <token>") | "bearer" ("Bearer <token>") | "none" (default: "none")
      token: "envvar://SPLUNK_HEC_TOKEN" # Entire string is secret URI; cleanly resolved by Keep's secret resolver
    headers:
      X-Custom-Header: "custom-value"
    batch_size: 100             # Max entries per batch before dispatch (default: 100)
    max_queued_batches: 10      # Max completed batches queued for dispatch before drop (default: 10)
    flush_interval_ms: 1000     # Max delay before shipping partial batch (default: 1000)
    timeout_ms: 5000            # HTTP client request timeout (default: 5000)
    max_retries: 0              # Max retry attempts for transient 5xx/network errors (default: 0)
    retry_backoff_ms: 200       # Backoff between retry attempts (default: 200)
    tls:
      ca_cert_file: ""          # Path to custom CA cert file on disk (optional)
      ca_cert_pem: ""           # Direct PEM certificate string or "vault://" / "envvar://" URI (optional)
      insecure_skip_verify: false

  # ============================================================================
  # OpenTelemetry OTLP/HTTP Log Sink Configuration (Active when sink: "otlp")
  # ============================================================================
  otlp:
    endpoint: "https://otel-collector.corp.internal:4318/v1/logs"
    auth:
      type: "bearer"            # Auth scheme: "bearer" ("Bearer <token>") | "splunk" | "none" (default: "none")
      token: "envvar://OTEL_TOKEN" # Entire string is secret URI
    headers:
      api-key: "envvar://OTEL_API_KEY"
    batch_size: 100             # Max entries per batch before dispatch (default: 100)
    max_queued_batches: 10      # Max completed batches queued for dispatch before drop (default: 10)
    flush_interval_ms: 1000     # Max delay before shipping partial batch (default: 1000)
    timeout_ms: 5000            # Export request timeout (default: 5000)
    max_retries: 0              # Max retry attempts for transient errors (default: 0)
    retry_backoff_ms: 200       # Backoff between retry attempts (default: 200)
    tls:
      ca_cert_file: ""          # Path to custom CA cert file on disk (optional)
      ca_cert_pem: ""           # Direct PEM certificate string or "vault://" / "envvar://" URI (optional)
      insecure_skip_verify: false
```

### Configuration Defaults

#### Top-Level Core Policies (Sink-Agnostic)
| Field | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `enabled` | `bool` | `false` | Master switch for MCP activity logging |
| `sink` | `string` | `"file"` | Active target sink: `"file"`, `"stdout"`, `"http"`, or `"otlp"` |
| `buffer_size` | `int` | `10000` | Fixed capacity of the in-memory log event queue |
| `truncate_payloads` | `bool` | `false` | Master toggle for argument and result payload truncation |
| `max_payload_bytes` | `int` | `4096` | Max byte threshold for payload truncation |
| `include_pdp_decision`| `*bool` | `false` | Whether to include PDP evaluation verdict in the request record |

#### Remote Network Sink Settings (`http` and `otlp` blocks)
| Field | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `encoding` | `string` | `"ndjson"` | Batch wire encoding for `http` sink: `"ndjson"` (Splunk HEC raw, Logstash) or `"json_array"` (Datadog API, OPA format, REST webhooks) |
| `batch_size` | `int` | `100` | Number of events accumulated before triggering an immediate network flush |
| `max_queued_batches` | `int` | `10` | Maximum completed batches queued in memory awaiting dispatch before non-blocking drop |
| `flush_interval_ms` | `int` | `1000` | Maximum milliseconds to buffer entries before flushing a partial batch |
| `timeout_ms` | `int` | `5000` | Timeout in milliseconds for HTTP client export requests |
| `max_retries` | `int` | `0` | Quick retry count on network timeout or HTTP 5xx responses |
| `retry_backoff_ms` | `int` | `200` | Milliseconds to wait before retrying a failed dispatch |
| `insecure_skip_verify`| `bool` | `false` | Whether to skip server TLS certificate verification (dev/test only) |

## Buffer Capacities & Memory Safety Architecture

To guarantee that remote SIEM outages, slow network links, or aggressive retry backoffs never exhaust Keep's heap memory or cause proxy tool calls to stall, the system uses a **three-tier bounded buffer architecture with a unified non-blocking drop policy**:

```text
Keep Handlers (Tools/Call)
          │
          ▼ [Tier 1: al.ch (Capacity: buffer_size = 10,000)]  <-- Non-blocking drop on full
Logger Worker Goroutine
          │
          ▼ Write() [Never blocks]
Sink Batch Accumulator [Tier 2: activeBatch slice (Capacity: batch_size = 100)]
          │
          ▼ [Tier 3: dispatchCh (Capacity: max_queued_batches = 10)] <-- Non-blocking drop on full
Dedicated Dispatcher Goroutine
          │ (Single-threaded HTTP POST with retries)
          ▼
Remote SIEM / OTel Collector
```

### Buffer Tier Specifications
1. **Tier 1: Core Activity Channel (`al.ch`)**:
   - **Capacity**: `buffer_size` (default: 10,000 entries).
   - **Producers**: Keep HTTP request handlers (`LogRequest`, `LogResponse`, `LogMalformedRequest`).
   - **Overflow Policy**: Non-blocking `select ... default`. If full, the incoming event is immediately dropped, and atomic metric `droppedCount` is incremented. Producers never wait or block.
2. **Tier 2: Sink Batch Accumulator (`activeBatch`)**:
   - **Capacity**: `batch_size` (default: 100 entries).
   - **Consumer**: `sink.Write()`.
   - **Trigger**: Appends entries under mutex. When length reaches `batch_size` or `flush_interval_ms` ticker fires, the accumulated slice is detached and handed off to Tier 3.
3. **Tier 3: Dispatcher Batch Channel (`dispatchCh`)**:
   - **Capacity**: `max_queued_batches` (default: 10 batches).
   - **Consumer**: Dedicated single-threaded network dispatcher goroutine.
   - **Overflow Policy**: Non-blocking `select ... default`. When Tier 2 hands off a batch, if `dispatchCh` is full (because the dispatcher is currently retrying a failed HTTP POST or experiencing slow network I/O), the completed batch is **immediately dropped**.
     - Atomic metrics `network_dropped_batches` and `network_dropped_entries` are incremented.
     - A rate-limited slog warning is emitted: `"remote sink dispatcher queue full; batch dropped"`.
     - `Write()` and the upstream logger worker **never block**.

### Bounded Event Count & Memory Allocation Estimates
In the fully saturated worst-case state:
1. Core channel queue (`al.ch`): holds up to `buffer_size` events (10,000).
2. Logger worker: 1 event actively being passed to `Write()`.
3. Sink accumulating buffer (`activeBatch`): holds up to `batch_size` events (100).
4. Dispatcher queue channel (`dispatchCh`): holds up to `max_queued_batches` batches ($10 \times 100 = 1,000$ events).
5. In-flight dispatching: 1 batch actively being serialized and transmitted over the network ($1 \times 100 = 100$ events).

$$\text{Max Queued Events} = \text{buffer\_size} + (\text{max\_queued\_batches} + 2) \times \text{batch\_size} + 1$$
Under default configuration:
$$10,000 + (10 + 2) \times 100 + 1 = 11,201 \text{ events maximum buffered in memory}$$

- **Memory Estimate with Truncation (`truncate_payloads: true`, threshold: 4096 bytes)**:
  Buffered events account for $\approx 46 \text{ MB}$. Adding transient serialized HTTP request body copies during active network dispatch ($\approx 1 \times \text{batch\_size} \times 4\text{ KB} \approx 400 \text{ KB}$) and standard Go HTTP transport buffers, total resident heap allocation across the activity logging subsystem is estimated and strictly bounded at $\approx 55 \text{ MB}$.
- **Memory Estimate without Truncation (`truncate_payloads: false`)**:
  Buffered events scale with $11,201 \times \text{event\_size}$ plus transient serialized request buffers. Even during an indefinite remote SIEM outage, memory cannot grow unboundedly because all tiers drop excess batches and events via non-blocking sends.

---

## Detailed Sink Implementation

### 1. HTTPS Batch Sink (`HTTPBatchSink`)

#### Wire Encodings & Endpoint Compatibility
The `HTTPBatchSink` supports two wire encodings via the `encoding` configuration setting:

1. **`encoding: "ndjson"` (Default)**:
   - Concatenates records as newline-delimited JSON-lines (`application/x-ndjson` or `application/json`):
     ```text
     {"timestamp":"2026-11-03T20:15:30.123Z","event":"mcp_request",...}\n
     {"timestamp":"2026-11-03T20:15:30.245Z","event":"mcp_response",...}\n
     ```
   - **Compatible With**:
     - **Splunk HEC Raw Endpoint**: `POST /services/collector/raw` with header `Authorization: Splunk <token>`.
     - **Intermediate Collectors**: Logstash (`http` input), Vector (`http_server` source), Fluentd (`in_http`), Fluent Bit (`http` input).
     - **Custom NDJSON Webhooks**: Any ingestion service expecting newline-separated JSON records.

2. **`encoding: "json_array"`**:
   - Encapsulates batched records inside a standard top-level JSON array with `Content-Type: application/json`:
     ```json
     [
       {"timestamp":"2026-11-03T20:15:30.123Z","event":"mcp_request",...},
       {"timestamp":"2026-11-03T20:15:30.245Z","event":"mcp_response",...}
     ]
     ```
   - **Compatible With**:
     - **Datadog Logs API**: `POST https://http-intake.logs.datadoghq.com/api/v2/logs` with header `DD-API-KEY: <key>`. Datadog's intake API natively accepts batches formatted as a JSON array of objects.
     - **OPA / Enterprise Decision Harvesters**: Follows the same JSON-array batching format used by Open Policy Agent decision logging.
     - **Standard REST Webhooks**: Corporate ingestion APIs and webhooks that require standard, syntactically complete JSON array payloads.

- **Explicit Incompatibility Note**:
  - **Elasticsearch / OpenSearch `_bulk` API**: The `_bulk` API strictly mandates an index action metadata line (e.g., `{"index": {}}\n`) immediately preceding every document line. Neither plain NDJSON nor a JSON array satisfies this requirement. Organizations routing directly to Elasticsearch/OpenSearch without Logstash/Vector should use the **`otlp` sink** directly to an OpenTelemetry Collector.

#### Batching Loop & Concurrency
- **Single-Threaded Sequential Dispatcher**:
  - To prevent unbounded goroutine creation and preserve strict FIFO delivery to SIEMs, `HTTPBatchSink` uses a dedicated single-threaded dispatcher goroutine reading batches from an internal queue channel.
  - `Write(line []byte)`: Appends entry bytes to an in-memory buffer slice under a mutex lock. If the slice reaches `batch_size`, the batch is transferred to the dispatcher channel and the buffer reset.
  - A background ticker fires every `flush_interval_ms` to flush any partial buffer.
  - **Sequential Network Dispatch**: The dispatcher processes one batch at a time:
    1. Formats the outbound payload using the encoding-specific batch serializer:
       - If `encoding == "ndjson"`: joins entries with newlines (`bytes.Join(batch, []byte("\n"))`), appends a trailing newline, and sets header `Content-Type: application/x-ndjson`.
       - If `encoding == "json_array"`: serializes entries into a top-level JSON array (`[` + `bytes.Join(batch, []byte(","))` + `]`) and sets header `Content-Type: application/json`.
       - Applies resolved authentication headers (`Authorization: Splunk <token>` or `Authorization: Bearer <token>` when `auth:` is configured) alongside custom `headers:`.
    2. Executes HTTP `POST` using a dedicated `http.Client` (configured with `timeout_ms` and custom `tls.Config`).
    3. Evaluates response status:
       - `2xx`: Success; batch discarded.
       - `4xx`: Non-retryable client error (e.g. 401 Unauthorized, 400 Bad Request, 403 Forbidden, 408 Request Timeout, 429 Too Many Requests). Logged to `slog.Error("http sink rejected batch", "status", code)`, metrics `network_dropped_batches` and `network_dropped_entries` incremented, and dropped immediately without retry. *Note: Neither 429 nor 408 triggers retries in this version; `Retry-After` header parsing and adaptive rate-limit backoff are reserved for commercial enterprise editions.*
       - `5xx` / Network Transport Error (Timeout, connection reset): Retryable error. Sleeps `retry_backoff_ms` and retries up to `max_retries`.
    4. If all retries fail: increment `networkDropCount` metric, log rate-limited `slog.Error("http sink delivery failed; batch dropped", "error", err)`, and drop the batch.
  - **Backpressure & Memory Safety**: If the dispatcher is paused during retry backoff, the channel fills up. Once full, calls to `Write` drop new entries via non-blocking send, guaranteeing process memory is never exhausted by SIEM downtime.
- **Graceful Shutdown & Bounded Caller Wait (`Close() error`)**:
  - `Close()` signals the dispatcher to stop accepting new batches and dispatches a final flush of whatever entries are currently buffered in memory.
  - The final network flush executes with an internal timeout context governed by `timeout_ms`.
  - While `ActivityLogger.Shutdown(ctx)` bounds how long the caller waits (returning `ctx.Err()` immediately if the caller's deadline expires), the underlying HTTP request is guaranteed to abort upon reaching `timeout_ms`, ensuring background goroutines never leak or run indefinitely.

---

### 2. OpenTelemetry Log Sink (`OTLPSink`)

#### OTLP/HTTP Protocol Specification
Rather than pulling in heavy SDK packages for log export, the `OTLPSink` formats batches according to the official W3C / OpenTelemetry standard JSON schema for `ExportLogsServiceRequest` (`application/json`):
- **Raw Entry Embedding**: The JSON entry passed to `Write(line []byte)` is placed directly into `logRecords[].body.stringValue = string(entry)`. This preserves the complete, unmodified audit entry without requiring double-unmarshaling or altering the `ActivitySink` interface.
- **Trace ID Hex Formatting**:
  - The OTLP specification strictly requires `logRecords[].traceId` to be a 32-character hexadecimal string (16 bytes hex-encoded).
  - For standard 36-character hyphenated UUIDs (e.g., `550e8400-e29b-41d4-a716-446655440000`), `OTLPSink` strips hyphens (`strings.ReplaceAll(traceID, "-", "")`) to produce the valid 32-character hex format.
  - If a `trace_id` is not valid 32-character hex (e.g., custom test strings), `traceId` on the log record is omitted/left blank, and the raw identifier is preserved under `attributes: [{ "key": "mcp.trace_id", "value": { "stringValue": rawTraceID } }]` to prevent OTel Collectors from rejecting the batch with HTTP 400 Bad Request.

```json
{
  "resourceLogs": [
    {
      "resource": {
        "attributes": [
          { "key": "service.name", "value": { "stringValue": "portcullis-keep" } },
          { "key": "telemetry.sdk.language", "value": { "stringValue": "go" } }
        ]
      },
      "scopeLogs": [
        {
          "scope": { "name": "portcullis.activity_log", "version": "1.0.0" },
          "logRecords": [
            {
              "timeUnixNano": "1730664930123456000",
              "observedTimeUnixNano": "1730664930123456000",
              "severityNumber": 9,
              "severityText": "INFO",
              "body": { "stringValue": "{\"event\":\"mcp_request\",...}" },
              "traceId": "4bf92f3577b34da6a3ce929d0e0e4736",
              "attributes": [
                { "key": "event.type", "value": { "stringValue": "mcp_request" } },
                { "key": "mcp.tool_name", "value": { "stringValue": "query_customers" } },
                { "key": "mcp.server_name", "value": { "stringValue": "database-mcp" } },
                { "key": "user.id", "value": { "stringValue": "alice@corp.internal" } }
              ]
            }
          ]
        }
      ]
    }
  ]
}
```

#### Transmission & Handling
- Dispatches HTTP `POST` to the configured `endpoint` (defaulting to `/v1/logs`) with `Content-Type: application/json`.
- Shares the identical retry, backoff, and best-effort drop logic as the HTTPS batch sink.
- Preserves distributed tracing correlation: extracts `trace_id` from the entry and populates `logRecords[].traceId` formatted as standard 32-character hex for native trace-log correlation in Grafana, Datadog, and Jaeger.

---

## Error Handling & Best-Effort Delivery

1. **Non-Blocking Proxy Hot Path**:
   - HTTP/OTLP network latency, connection stalls, or retry backoffs take place strictly inside the background worker goroutine or flush loop.
   - Incoming tool calls handled by Gate and Keep never block, pause, or wait on network I/O.
2. **Bounded In-Memory Buffers**:
   - The queue between Keep handlers and the network sink is bounded by `buffer_size` (10,000 entries).
   - If the remote SIEM is down and the buffer fills, the producer drops incoming entries immediately via non-blocking send.
3. **Audit Visibility**:
   - Atomic diagnostic metrics: `http_exported_entries`, `http_failed_batches`, `http_dropped_entries`.
   - Metrics are exposed via Keep's health and diagnostic status endpoints.
4. **No Automatic File Fallback (Privacy & Compliance Principle)**:
   - If a remote network sink encounters a misconfiguration (e.g. malformed URL, invalid CA cert, missing token) or total network failure, Keep logs the operational problem to its standard process log (`slog`).
   - **For privacy and compliance reasons, `mcp_activity_log` NEVER falls back to local file logging**. Silently spilling sensitive MCP prompts, tool arguments, or tool responses to local host disk when an administrator explicitly configured a network sink would violate the organization's data-at-rest privacy mandates (e.g. HIPAA, SOC 2, GDPR). In a remote sink failure scenario, records are dropped non-blockingly rather than ever touching local storage.

## Secret Allowlist & Secret Resolution (`envvar://` & `vault://`)

Portcullis configuration supports URI-based secret resolution:
- **Unrestricted Schemes (`envvar://`, `filevar://`)**: May appear in any configuration field where the entire value is a secret URI (e.g., `token: "envvar://SPLUNK_TOKEN"` or `api-key: "envvar://OTEL_API_KEY"`). The secret resolver resolves full string values and does not perform substring interpolation inside prefixed strings.
- **Restricted Schemes (`vault://`)**: HashiCorp Vault KV v2 secret resolution is strictly restricted to fields enumerated in Keep's `SecretAllowlist` to prevent untrusted config injection.

### Keep Secret Allowlist Updates (`internal/keep/config.go`)
The following paths will be added to `keep.SecretAllowlist`:
- `"mcp_activity_log.http.auth.token"`
- `"mcp_activity_log.http.headers"`
- `"mcp_activity_log.http.tls.ca_cert_pem"`
- `"mcp_activity_log.otlp.auth.token"`
- `"mcp_activity_log.otlp.headers"`
- `"mcp_activity_log.otlp.tls.ca_cert_pem"`

### Map Traversal & Prefix Allowlisting (`internal/shared/secrets/resolver.go`)
Because `http.headers` and `otlp.headers` are `map[string]string` fields, the reflection walker creates child paths formatted as `mcp_activity_log.http.headers.<HeaderName>` (e.g. `mcp_activity_log.http.headers.X-Custom-Token`).
- `secrets.ResolveConfig` checks allowlist membership using prefix matching: if a parent map path (e.g. `mcp_activity_log.http.headers`) is present in `allowset`, any child key under that map is permitted to resolve `vault://` secrets.
- Similarly, `cfgloader.BuildPostureReport` (`internal/shared/config/posture.go`) redacts allowlisted header values as `"[REDACTED]"` in startup security posture attestations, ensuring SIEM tokens never leak in plaintext reports.

---

## Verification Plan

### Automated Tests
1. **HTTP Batch Sink Unit Tests (`internal/keep/activitylog/http_sink_test.go`)**:
   - **Wire Encodings (`ndjson` vs `json_array`)**:
     - Verify `encoding: "ndjson"` produces newline-separated JSON lines with header `Content-Type: application/x-ndjson`.
     - Verify `encoding: "json_array"` produces a valid top-level JSON array (`[ {...}, {...} ]`) with header `Content-Type: application/json`.
   - **Batch Threshold**: Enqueue entries up to `batch_size`; assert HTTP POST is triggered immediately with all entries formatted.
   - **Ticker Interval**: Enqueue fewer entries than `batch_size`; advance time past `flush_interval_ms`; assert partial batch is dispatched.
   - **Dispatcher Queue Full / Non-Blocking Drop**:
     - Pause the mock HTTP server or inject backoff delay so the dispatcher is busy.
     - Enqueue entries filling `max_queued_batches` (10 batches).
     - Enqueue an 11th batch; assert `Write` does NOT block, the 11th batch is immediately dropped, and `network_dropped_batches` is incremented.
   - **Retry & Recovery**: Configure a mock HTTP server that returns `503 Service Unavailable` twice before returning `200 OK`; verify batch succeeds after 2 retries without drops.
   - **Exhaustion & Drop**: Configure a mock server returning continuous `500 Internal Server Error`; verify batch drops after `max_retries`, increments `dropped_entries`, and does not panic or hang.
   - **Non-Retryable 4xx (including 429 & 408)**: Configure mock server returning `401 Unauthorized`, `408 Request Timeout`, and `429 Too Many Requests`; verify batches are dropped immediately without retries or `Retry-After` sleeps, and `network_dropped_batches` is incremented.
   - **Shutdown Flush**: Enqueue entries and immediately call `Close()`; verify mock server receives remaining entries before shutdown exits.
2. **OTLP Sink Unit Tests (`internal/keep/activitylog/otlp_sink_test.go`)**:
   - Verify serialization to valid OTLP `ExportLogsServiceRequest` JSON.
   - Verify `trace_id` is properly extracted and encoded in `traceId`.
   - Verify custom headers (e.g. `api-key`) and TLS client configuration are correctly applied to the outbound request.
3. **Keep End-to-End Network Sink Test (`internal/keep/server_activity_network_test.go`)**:
   - Start Keep with `mcp_activity_log.sink: "http"` pointing to a mock SIEM test server.
   - Execute tool calls through Keep.
   - Assert the mock SIEM receives batched `mcp_request` and `mcp_response` events over HTTP with valid headers and payloads.
   - Confirm zero activity log files are created in the local workspace directory.
