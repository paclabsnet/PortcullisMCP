# Performance Monitoring & Metrics Design Specification

**Status:** Approved / In Review  
**Date:** 2026-11-06  
**Target Version:** v0.7.0  
**Authors:** PAC.Labs / Portcullis Architecture  
**Tracking Document:** `docs/development/tracking/2026-11-06-performance-monitoring-tracking.md`  
**Roadmap Task:** `docs/roadmap.md` (`### Task: Add performance monitoring to Portcullis`)

---

## 1. Executive Summary & Objective

Portcullis requires production-ready performance monitoring and observability across its distributed components (**Keep**, **Guard**, and **Gate**). While distributed tracing is currently supported via OpenTelemetry (`internal/telemetry`), metrics collection has remained fragmented or temporarily coupled to readiness probes (such as `activity_log` counters returned in Keep's `/readyz` response).

This design specification establishes a standardized, enterprise-grade metrics architecture based on **OpenTelemetry Metrics SDK with an Embedded Prometheus Exporter**. It defines:
1. Standardized metric instruments for HTTP performance, Policy Decision Point (PDP) evaluations, MCP backend interactions, escalation token lifecycles, and audit log exports.
2. An embedded pull-based `/metrics` endpoint exposed across Portcullis-Keep, Portcullis-Guard, and Multi-Tenant Portcullis-Gate.
3. Explicit exclusion of Single-Tenant Portcullis-Gate from metrics reporting (maintaining zero-overhead CLI and stdio operation).
4. Strict separation of health/readiness concerns from telemetry by removing diagnostic delivery statistics from `/readyz`.
5. Bounded label dimensions to guarantee zero cardinality explosion in production environments.

---

## 2. Goals & Non-Goals

### 2.1 Goals
- **OpenTelemetry Standard API**: Instrument all application logic using official `go.opentelemetry.io/otel/metric` abstractions (Counters, UpDownCounters, Histograms, and Observable Gauges/Counters).
- **Embedded Prometheus Pull Exporter**: Serve Prometheus-compatible scrapable text metrics at `GET /metrics` on Keep, Guard, and Multi-Tenant Gate.
- **Detailed Subsystem Observability**:
  - **Keep**: Inbound HTTP request throughput and latency; PDP authorization decisions (`allow`, `deny`, `escalate`, `workflow`, `error`) and evaluation durations; MCP backend proxy latencies and connection failures; activity log delivery statistics.
  - **Guard**: Escalation token minting (UI approvals and direct deposits), claims, pending escalation lifecycles, and listener performance.
  - **Multi-Tenant Gate**: Inbound MCP HTTP request latency and throughput; tool execution routing (localfs fast-path vs Keep PDP); escalation resolution outcomes; active session counts.
- **Readiness Probe Cleansing**: Transition diagnostic delivery counters out of Keep's `/readyz` JSON payload and into standard Prometheus metric counters.
- **Safe Cardinality**: Ensure label sets are strictly bounded to fixed enums and predefined IDs, preventing memory leaks in metric registries.
- **Graceful Lifecycle**: Provide clean shutdown semantics flushing in-memory metric collections during process termination.

### 2.2 Non-Goals
- **Single-Tenant Gate Metrics**: Single-Tenant Gate runs in stdio or local-forwarding mode where no persistent HTTP listener exists. Per roadmap mandates, Single-Tenant Gate will not report metrics or open a scraping port.
- **Direct Push to Remote TSDBs**: Out-of-the-box support is focused on standard Prometheus pull scraping (`/metrics`). Push-based remote write (such as InfluxDB line protocol, Datadog DogStatsD UDP, or direct Cortex/Mimir push) is deferred; organizations wishing to push to remote monitoring can route via OpenTelemetry Collector or Prometheus Agent.
- **High-Cardinality Dimensions**: Metric labels will never include user emails, session IDs, auth tokens, prompt text, tool arguments, or arbitrary exception messages.

---

## 3. Architecture & Telemetry Pipeline

```
┌────────────────────────────────────────────────────────────────────────┐
│                        Portcullis Application Logic                    │
│   (Keep Server / Router, Guard Token Store, Multi-Tenant Gate Handler) │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                         otel/metric Instruments
                 (Counters, Histograms, Observable Callbacks)
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                      internal/telemetry Package                        │
│                                                                        │
│   ┌────────────────────────┐            ┌──────────────────────────┐   │
│   │ sdktrace.TracerProvider│            │ sdkmetric.MeterProvider  │   │
│   │ (OTLP / stdout / noop) │            │  - Resource Attributes   │   │
│   └────────────────────────┘            │  - Periodic / Manual Rdr │   │
│                                         └────────────┬─────────────┘   │
│                                                      │                 │
│                                           otel/exporters/prometheus    │
│                                                      │                 │
│                                                      ▼                 │
│                                         Prometheus Scrape Registry     │
│                                                      │                 │
│                                                      ▼                 │
│                                           telemetry.MetricsHandler()   │
└──────────────────────────────────────────────────────┬─────────────────┘
                                                       │
                                          GET /metrics HTTP Endpoint
                                                       │
                                                       ▼
                                         External Prometheus / Agent
```

### 3.1 MeterProvider Setup (`internal/telemetry/provider.go`)
The `internal/telemetry` package manages both tracing and metrics:
1. `telemetry.Setup(ctx, cfg)` initializes:
   - The global `sdktrace.TracerProvider`.
   - An `sdkmetric.MeterProvider` configured with standard resource attributes (`service.name`, `service.version`, `os`, `process`).
   - An embedded Prometheus exporter (`go.opentelemetry.io/otel/exporters/prometheus`).
2. Returns a unified `shutdown` callback that cleanly terminates both trace batchers and metric readers.
3. Exposes `telemetry.MetricsHandler() http.Handler` which serves the Prometheus registry via `promhttp.Handler()`.

### 3.2 Configuration Schema (`unified.go`)
The `OperationsConfig.Telemetry` structure in `internal/shared/config/unified.go` is extended with metrics settings:

```yaml
operations:
  telemetry:
    exporter: "otlp"          # Tracing exporter: "otlp" | "stdout" | "noop"
    service_name: "portcullis-keep"
    otlp:
      endpoint: "https://otel-collector.corp.internal:4318"
      headers:
        api-key: "envvar://OTEL_API_KEY"
    metrics:
      enabled: true           # Enable /metrics endpoint (default: true for Keep, Guard, MT-Gate)
      path: "/metrics"        # Scrape endpoint path (default: "/metrics")
```

---

## 4. Component Instrumentation Specifications

### 4.1 Portcullis-Keep

Keep is the central policy enforcement and routing engine. Its metrics provide visibility into client traffic, authorization decisions, upstream tool latencies, and audit log exports.

#### 4.1.1 HTTP Server Metrics
| Metric Name | Type | Unit | Description | Labels |
|---|---|---|---|---|
| `portcullis_keep_http_requests_total` | Counter | `{request}` | Total inbound HTTP requests to Keep. | `endpoint`, `method`, `status_code` |
| `portcullis_keep_http_request_duration_seconds` | Histogram | `s` | Latency distribution of inbound HTTP requests. | `endpoint`, `method` |

- `endpoint` values are strictly normalized route patterns: `"/mcp"`, `"/healthz"`, `"/readyz"`, `"/metrics"`, `"/admin/reload"`, `"/oauth/callback"`. Unmatched routes are recorded as `"other"`.
- `status_code` values are canonical 3-digit strings (`"200"`, `"400"`, `"401"`, `"403"`, `"500"`, `"503"`).

#### 4.1.2 Policy Decision Point (PDP) Metrics
Instrumented in `internal/keep/pdp.go`:
| Metric Name | Type | Unit | Description | Labels |
|---|---|---|---|---|
| `portcullis_keep_pdp_decisions_total` | Counter | `{decision}` | Total authorization decisions evaluated. | `decision`, `policy_engine`, `cached` |
| `portcullis_keep_pdp_duration_seconds` | Histogram | `s` | Evaluation duration for PDP authorization checks. | `decision`, `policy_engine` |

- `decision` values: `"allow"`, `"deny"`, `"escalate"`, `"workflow"`, `"error"`.
- `policy_engine` values: `"rego"`, `"cedar"`, `"permit"`, `"mock"`.
- `cached` values: `"true"`, `"false"`.

#### 4.1.3 MCP Backend Proxy Metrics
Instrumented in `internal/keep/router.go`:
| Metric Name | Type | Unit | Description | Labels |
|---|---|---|---|---|
| `portcullis_keep_mcp_backend_calls_total` | Counter | `{call}` | Total forwarded requests to destination MCP servers. | `backend_id`, `status` |
| `portcullis_keep_mcp_backend_duration_seconds` | Histogram | `s` | Execution latency of remote MCP backend tool calls. | `backend_id` |

- `backend_id` values: Identifier defined in `responsibility.backends` (e.g. `"github"`, `"jira"`, `"localfs"`). Unconfigured/dynamic backends fallback to `"unknown"`.
- `status` values: `"success"`, `"error"`, `"timeout"`.

#### 4.1.4 Activity Log Delivery Metrics
Instrumented via OpenTelemetry Observable Counters bound to `activitylog.Stats()`:
| Metric Name | Type | Unit | Description | Labels |
|---|---|---|---|---|
| `portcullis_keep_activity_log_buffer_dropped_total` | Counter | `{entry}` | Entries dropped due to full in-memory buffer channel. | None |
| `portcullis_keep_activity_log_exported_entries_total` | Counter | `{entry}` | Total entries successfully delivered to the active sink. | `sink` (`file`, `stdout`, `http`, `otlp`) |
| `portcullis_keep_activity_log_sink_dropped_batches_total` | Counter | `{batch}` | Batches dropped by remote sinks due to queue overflow or delivery error. | `sink` (`http`, `otlp`) |
| `portcullis_keep_activity_log_sink_dropped_entries_total` | Counter | `{entry}` | Entries dropped by remote sinks due to network exhaustion or non-retryable 4xx. | `sink` (`http`, `otlp`) |

#### 4.1.5 Readiness Endpoint Cleansing (`/readyz`)
Keep's `handleReadyz` method in `internal/keep/server.go` currently includes:
```json
{
  "status": "ready",
  "tools": 14,
  "signer_configured": true,
  "activity_log": {
    "buffer_dropped": 0,
    "exported_entries": 1284,
    "sink_dropped_batches": 0,
    "sink_dropped_entries": 0
  }
}
```
In accordance with roadmap requirements, the `"activity_log"` key is removed from `/readyz`. Readiness probes now solely attest whether Keep can list tools and serve traffic, leaving delivery statistics to `/metrics`.

---

### 4.2 Portcullis-Guard

Guard manages human-in-the-loop escalation approvals, token creation, and token verification.

#### 4.2.1 Escalation Token Metrics
Instrumented in `internal/guard/server.go` and `internal/guard/store.go`:
| Metric Name | Type | Unit | Description | Labels |
|---|---|---|---|---|
| `portcullis_guard_escalation_tokens_created_total` | Counter | `{token}` | Total signed escalation tokens generated. | `method`, `status` |
| `portcullis_guard_escalation_tokens_claimed_total` | Counter | `{token}` | Total token claim requests processed. | `status` |
| `portcullis_guard_pending_requests_total` | Counter | `{request}` | Lifecycle events for pending escalation records. | `action` |

- `method` values: `"ui_approval"` (human approved in browser), `"direct_deposit"` (machine API deposit).
- `status` values for created: `"success"`, `"failed"`.
- `status` values for claimed: `"success"`, `"not_found"`, `"expired"`.
- `action` values for pending: `"stored"`, `"approved"`, `"rejected"`, `"expired"`.

#### 4.2.2 Guard HTTP Metrics
| Metric Name | Type | Unit | Description | Labels |
|---|---|---|---|---|
| `portcullis_guard_http_requests_total` | Counter | `{request}` | Total inbound HTTP requests to Guard. | `listener`, `endpoint`, `status_code` |
| `portcullis_guard_http_duration_seconds` | Histogram | `s` | Latency distribution of Guard endpoints. | `listener`, `endpoint` |

- `listener` values: `"api"` (`token_api`), `"ui"` (`approval_ui`).
- `endpoint` values: `"/approve"`, `"/token/deposit"`, `"/token/claim"`, `"/pending"`, `"/healthz"`, `"/readyz"`, `"/metrics"`, `"/auth/login"`, `"/auth/callback"`.

#### 4.2.3 Endpoint Mounting
- `GET /metrics` is mounted on both `apiMux` and `uiMux` using `telemetry.MetricsHandler()`.
- Machine network scrapers typically scrape `token_api` on its mTLS or machine listener, while internal monitoring can also verify `approval_ui`.

---

### 4.3 Portcullis-Gate (Multi-Tenant Mode)

Multi-Tenant Gate serves as the perimeter reverse-proxy terminating agent HTTP connections, enforcing session authentication, evaluating local filesystem fast-paths, and delegating tool requests to Keep.

#### 4.3.1 Gate HTTP Metrics
| Metric Name | Type | Unit | Description | Labels |
|---|---|---|---|---|
| `portcullis_gate_http_requests_total` | Counter | `{request}` | Inbound HTTP requests received by Gate. | `endpoint`, `status_code` |
| `portcullis_gate_http_duration_seconds` | Histogram | `s` | Latency of Gate HTTP request processing. | `endpoint` |

- `endpoint` values: `"/mcp"`, `"/healthz"`, `"/readyz"`, `"/metrics"`.
- Bypasses authentication: `GET /metrics` is added to the unauthenticated path allowlist alongside `/healthz` and `/readyz` in `internal/gate/mcp_http.go`.

#### 4.3.2 Tool Execution & PDP Verdict Metrics
Instrumented in `internal/gate/server.go`:
| Metric Name | Type | Unit | Description | Labels |
|---|---|---|---|---|
| `portcullis_gate_tool_calls_total` | Counter | `{call}` | Total tool calls processed by Gate. | `tool_name`, `decision`, `source` |
| `portcullis_gate_tool_call_duration_seconds` | Histogram | `s` | End-to-end tool call latency as observed by Gate. | `tool_name`, `decision` |
| `portcullis_gate_escalation_claims_total` | Counter | `{claim}` | Outcomes of escalation token claim attempts. | `status` |

- `tool_name` values: Verified against registered tools list. Unrecognized or dynamic tools collapse to `"unknown"` to prevent cardinality growth.
- `decision` values: `"allow"`, `"deny"`, `"escalate"`, `"workflow"`, `"error"`.
- `source` values: `"fastpath"` (local filesystem pre-eval), `"keep"` (delegated to Portcullis-Keep).
- `status` values for escalation claims: `"claimed"`, `"timeout"`, `"error"`.

#### 4.3.3 Active Sessions
| Metric Name | Type | Unit | Description | Labels |
|---|---|---|---|---|
| `portcullis_gate_active_sessions` | UpDownCounter / Gauge | `{session}` | Number of currently tracked active client sessions. | None |

---

### 4.4 Portcullis-Gate (Single-Tenant Mode)

Per explicit roadmap design:
- Single-Tenant Gate executes as a dedicated agent-bound sidecar or CLI subprocess communicating via `stdio`.
- Single-Tenant Gate **does not** initialize the metrics subsystem, does not bind a scrape port, and does not record performance counters.
- Telemetry calls compile to no-op invocations.

---

## 5. Metric Cardinality & Protection Rules

Metric cardinality explosion is a critical operational risk for Prometheus. The following invariant boundaries are strictly enforced:

1. **No User or Session Identity in Labels**:
   `user_id`, `client_id`, `agent_id`, `session_id`, `trace_id`, and `token_fingerprint` MUST NEVER appear as metric labels. They belong in structured logs (`slog`), trace span attributes, or activity logs.
2. **Fixed Enumerations for Statuses and Errors**:
   Error messages, exception stack traces, and dynamic HTTP failure strings MUST NOT be passed into metric labels. Instead, errors are mapped to fixed categories (`"network_error"`, `"timeout"`, `"auth_error"`, `"rejected"`).
3. **Route Normalization**:
   All HTTP path dimensions must be canonical routes. Raw query parameters (`?code=...`), token hashes, or REST path parameters (`/token/{id}`) must be stripped to static template names (`"/token/claim"`).
4. **Tool Name Sanitization**:
   If an incoming MCP request references a tool that is not in the configured tool set, it is categorized as `"tool_name": "unknown"` to prevent malicious agents from bloating Prometheus memory with random strings.

---

## 6. Implementation Architecture

### 6.1 OpenTelemetry Packages Required
- `go.opentelemetry.io/otel/metric`: Metric instrument definitions.
- `go.opentelemetry.io/otel/sdk/metric`: SDK implementation and periodic/manual readers.
- `go.opentelemetry.io/otel/exporters/prometheus`: Prometheus exporter and metric reader bridge.
- `github.com/prometheus/client_golang/prometheus/promhttp`: HTTP scrape handler.

### 6.2 Telemetry Provider Interface (`internal/telemetry`)
```go
package telemetry

import (
    "context"
    "net/http"
    "go.opentelemetry.io/otel/metric"
)

// Setup initializes tracing and metrics according to cfg.
// Returns a shutdown function that flushes and cleans up both providers.
func Setup(ctx context.Context, cfg Config) (shutdown func(context.Context) error, err error)

// Meter returns a named OpenTelemetry Meter from the global MeterProvider.
func Meter(name string) metric.Meter

// MetricsHandler returns an http.Handler that serves the Prometheus scrape endpoint.
func MetricsHandler() http.Handler
```

### 6.3 HTTP Middleware for Request Tracking
A shared HTTP middleware in `internal/shared/middleware/metrics.go` will automatically record request counts, status codes, and latencies for standard HTTP routers without code duplication across Keep and Guard:
```go
func HTTPMetricsMiddleware(meter metric.Meter, component string) func(http.Handler) http.Handler
```

---

## 7. Migration & Backward Compatibility

1. **Zero-Configuration Defaults**:
   If `operations.telemetry.metrics` is omitted in YAML, metrics are enabled by default for Keep, Guard, and Multi-Tenant Gate, serving on `/metrics`.
2. **Readiness Probe Transition**:
   - Clients scraping Keep's `/readyz` for `activity_log` counters must transition to scraping `/metrics`.
   - The `"activity_log"` field in Keep's `/readyz` response is deprecated and removed in v0.7.0.
   - Status, tool counts, and signer status remain intact in `/readyz`.
3. **Existing Tracing Preserved**:
   TracerProvider initialization, W3C trace context propagation, and span parenting remain completely unaffected.

---

## 8. Verification & Test Strategy

### 8.1 Unit Tests
- **Telemetry Package Tests (`internal/telemetry/provider_test.go`)**:
  - Test `Setup` with metrics enabled; verify `MetricsHandler()` returns `200 OK` and Prometheus header `Content-Type: text/plain; version=0.0.4`.
  - Test `Setup` in no-op mode; verify metric instruments record without panic and `MetricsHandler()` handles scrape requests gracefully.
  - Verify shutdown cleanly releases resources.
- **Keep HTTP Middleware Tests (`internal/keep/server_metrics_test.go`)**:
  - Perform test requests to `/mcp`, `/readyz`, and verify `portcullis_keep_http_requests_total` increments with appropriate status codes and paths.
  - Verify `/readyz` response does NOT contain `"activity_log"`.
- **PDP Metrics Tests (`internal/keep/pdp_test.go`)**:
  - Mock allow, deny, and escalate decisions; verify `portcullis_keep_pdp_decisions_total` counter values and `portcullis_keep_pdp_duration_seconds` histogram recordings.
- **Activity Log Observable Counters (`internal/keep/activitylog/metrics_test.go`)**:
  - Populate activity log stats; scrape Prometheus handler; assert `portcullis_keep_activity_log_exported_entries_total` and `buffer_dropped` match atomic counter state.
- **Guard Token Metrics Tests (`internal/guard/server_metrics_test.go`)**:
  - Deposit tokens, claim tokens, submit UI approvals; assert `portcullis_guard_escalation_tokens_created_total` and `claimed_total` counters.
  - Verify `GET /metrics` returns 200 on both `apiMux` and `uiMux`.
- **Multi-Tenant Gate Tests (`internal/gate/mcp_http_test.go`)**:
  - Execute tool calls through Gate; scrape `/metrics`; verify tool call counters and decision labels.
  - Confirm `/metrics` bypasses session authentication.
- **Single-Tenant Gate Tests**:
  - Confirm Single-Tenant Gate starts without metric registrations or listeners.

### 8.2 End-to-End Prometheus Scrape Verification
- Deploy demo or integration test environment.
- Run `curl -fsS http://localhost:<port>/metrics`.
- Verify standard Prometheus line format, correct `# TYPE` and `# HELP` annotations, and non-empty metric outputs.
