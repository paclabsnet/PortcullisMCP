# Remote Activity Log Sinks Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Provide zero-local-disk audit logging for Keep by implementing an HTTPS Batch Sink (`http`) and an OpenTelemetry Log Sink (`otlp`) that stream activity events directly into remote SIEMs or OTel Collectors over TLS from process memory.

**Architecture:** Keep's `ActivityLogger` delegates serialized JSON lines to an `ActivitySink` interface. For remote sinks (`http` and `otlp`), lines accumulate in a bounded in-memory batch buffer and are handed off non-blockingly to a dedicated single-threaded dispatcher goroutine that serializes batches (`ndjson`, `json_array`, or OTLP JSON) and dispatches them sequentially with bounded retries. Strict non-blocking overflow policies across all three buffer tiers guarantee bounded memory ($\le 55\text{ MB}$) and zero file-fallback under outages or misconfiguration.

**Tech Stack:** Go 1.25, `net/http`, `crypto/tls`, standard library `log/slog`, `sync/atomic`.

**Spec:** `docs/development/specs/2026-11-03-remote-activity-log-sinks-design.md`

## Global Constraints
- Target Go version: 1.25.0 (`go.mod`).
- Zero local disk footprint: When `sink: "http"` or `sink: "otlp"`, no files are created, opened, or rotated.
- Zero fallback: Remote sink failure or misconfiguration must log to `slog` and drop events, NEVER falling back to local file logging.
- Memory safety: Three-tier bounded buffers (`buffer_size: 10000`, `batch_size: 100`, `max_queued_batches: 10`) capped at $11,201$ events ($\approx 55\text{ MB}$ with truncation).
- Wire encodings: `http` sink supports `encoding: "ndjson"` (default) and `encoding: "json_array"` (Datadog API, OPA format, REST webhooks).
- 4xx handling: HTTP 4xx responses (including 408 and 429) are treated as terminal non-retryable drops; `Retry-After` rate limiting is an enterprise non-goal.
- Secret resolution: `auth.token`, `tls.ca_cert_pem`, and `headers` values must be entire secret URIs (`envvar://`, `vault://`); `keep.SecretAllowlist` supports prefix matching for map elements.

## Review Focus
1. **`vault://` URI in map headers**: Must correctly resolve when parent map is in `keep.SecretAllowlist` and reject when not allowlisted.
2. **Arbitrary non-hex `trace_id` in OTLP**: Must omit `logRecords[].traceId` and preserve in `attributes` so OTel Collectors never reject with HTTP 400.
3. **HTTP 429 / 408 responses from SIEM**: Must drop batch immediately without retrying or sleeping on `Retry-After`.
4. **Remote sink misconfiguration**: Must log to operational `slog` and NEVER fall back to local file logging.
5. **Dispatcher queue full under SIEM outage**: Must drop excess batches via non-blocking send without blocking `Write()` or proxy tool execution.

---

### Task 1: Secret Resolver Prefix Allowlisting & Keep SecretAllowlist Updates

**Files:**
- Modify: `internal/shared/secrets/resolver.go:150-185`
- Modify: `internal/keep/config.go:30-55`
- Test: `internal/shared/secrets/resolver_test.go`
- Test: `internal/keep/config_test.go`

**Interfaces:**
- Produces:
  ```go
  // In internal/shared/secrets/resolver.go:
  func isFieldAllowlisted(path string, allowset map[string]bool) bool
  ```
- Updates `keep.SecretAllowlist`:
  - `"mcp_activity_log.http.auth.token"`
  - `"mcp_activity_log.http.headers"`
  - `"mcp_activity_log.http.tls.ca_cert_pem"`
  - `"mcp_activity_log.otlp.auth.token"`
  - `"mcp_activity_log.otlp.headers"`
  - `"mcp_activity_log.otlp.tls.ca_cert_pem"`

- [ ] **Step 1: Write test for prefix allowlisting on map keys in secret resolver**

Add to `internal/shared/secrets/resolver_test.go`:
```go
func TestResolveConfig_AllowlistedMapPrefix(t *testing.T) {
	const (
		testMount  = "secret"
		testPath   = "testpath"
		testKey    = "mykey"
		testSecret = "resolved-token"
	)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{
				"data": map[string]any{testKey: testSecret},
			},
		})
	})
	ts := httptest.NewServer(handler)
	defer ts.Close()

	t.Setenv("VAULT_ADDR", ts.URL)
	t.Setenv("VAULT_TOKEN", "test-token")

	type ConfigWithMap struct {
		Headers map[string]string `yaml:"headers"`
		Other   map[string]string `yaml:"other"`
	}
	cfg := &ConfigWithMap{
		Headers: map[string]string{
			"DD-API-KEY": fmt.Sprintf("vault://%s/%s#%s", testMount, testPath, testKey),
		},
		Other: map[string]string{
			"SECRET": fmt.Sprintf("vault://%s/%s#%s", testMount, testPath, testKey),
		},
	}
	// "headers" is allowlisted, "other" is NOT allowlisted.
	_, err := ResolveConfig(context.Background(), cfg, []string{"headers"})
	if err == nil || !strings.Contains(err.Error(), "is not permitted at field \"other.SECRET\"") {
		t.Fatalf("expected error on non-allowlisted map field 'other.SECRET', got: %v", err)
	}

	// Resolve with only allowlisted map
	cfg.Other = nil
	sources, err := ResolveConfig(context.Background(), cfg, []string{"headers"})
	if err != nil {
		t.Fatalf("unexpected error on allowlisted map key: %v", err)
	}
	if cfg.Headers["DD-API-KEY"] != testSecret {
		t.Errorf("got %q, want %q", cfg.Headers["DD-API-KEY"], testSecret)
	}
	if sources["headers.DD-API-KEY"] != "vault" {
		t.Errorf("unexpected source for headers.DD-API-KEY: %v", sources)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test -v ./internal/shared/secrets -run TestResolveConfig_AllowlistedMapPrefix`
Expected: FAIL ("is not permitted at field 'headers.DD-API-KEY'")

- [ ] **Step 3: Implement prefix allowlist matching and update `keep.SecretAllowlist`**

1. In `internal/shared/secrets/resolver.go`:
   Replace exact lookup `if !allowset[path]` with prefix-aware helper:
   ```go
   func isFieldAllowlisted(path string, allowset map[string]bool) bool {
       if allowset[path] {
           return true
       }
       for p := range allowset {
           if strings.HasPrefix(path, p+".") {
               return true
           }
       }
       return false
   }
   ```
2. In `internal/keep/config.go`:
   Add remote sink paths to `SecretAllowlist`:
   ```go
   "mcp_activity_log.http.auth.token",
   "mcp_activity_log.http.headers",
   "mcp_activity_log.http.tls.ca_cert_pem",
   "mcp_activity_log.otlp.auth.token",
   "mcp_activity_log.otlp.headers",
   "mcp_activity_log.otlp.tls.ca_cert_pem",
   ```

- [ ] **Step 4: Run secret resolver tests to verify they pass**

Run: `go test -v ./internal/shared/secrets/...`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/shared/secrets/resolver.go internal/shared/secrets/resolver_test.go internal/keep/config.go
git commit -m "feat(secrets): support prefix allowlisting for map keys and add remote activity log sink paths"
```

---

### Task 2: Configuration Schemas & Validation for HTTP and OTLP Sinks

**Files:**
- Modify: `internal/shared/config/unified.go`
- Modify: `internal/keep/config.go`
- Test: `internal/keep/config_test.go`

**Interfaces:**
- Produces:
  ```go
  type HTTPActivityAuthConfig struct {
      Type  string `yaml:"type"`  // "splunk" | "bearer" | "none"
      Token string `yaml:"token"` // secret URI
  }
  type ActivityTLSConfig struct {
      CACertFile         string `yaml:"ca_cert_file"`
      CACertPEM          string `yaml:"ca_cert_pem"`
      InsecureSkipVerify bool   `yaml:"insecure_skip_verify"`
  }
  type HTTPActivitySinkConfig struct {
      URL              string                 `yaml:"url"`
      Encoding         string                 `yaml:"encoding"` // "ndjson" | "json_array"
      Auth             HTTPActivityAuthConfig `yaml:"auth"`
      Headers          map[string]string      `yaml:"headers"`
      BatchSize        int                    `yaml:"batch_size"`
      MaxQueuedBatches int                    `yaml:"max_queued_batches"`
      FlushIntervalMS  int                    `yaml:"flush_interval_ms"`
      TimeoutMS        int                    `yaml:"timeout_ms"`
      MaxRetries       int                    `yaml:"max_retries"`
      RetryBackoffMS   int                    `yaml:"retry_backoff_ms"`
      TLS              ActivityTLSConfig      `yaml:"tls"`
  }
  type OTLPActivitySinkConfig struct {
      Endpoint         string                 `yaml:"endpoint"`
      Auth             HTTPActivityAuthConfig `yaml:"auth"`
      Headers          map[string]string      `yaml:"headers"`
      BatchSize        int                    `yaml:"batch_size"`
      MaxQueuedBatches int                    `yaml:"max_queued_batches"`
      FlushIntervalMS  int                    `yaml:"flush_interval_ms"`
      TimeoutMS        int                    `yaml:"timeout_ms"`
      MaxRetries       int                    `yaml:"max_retries"`
      RetryBackoffMS   int                    `yaml:"retry_backoff_ms"`
      TLS              ActivityTLSConfig      `yaml:"tls"`
  }
  func (c *MCPActivityLogConfig) Validate() error
  ```

- [ ] **Step 1: Write configuration parsing and validation tests for remote sinks**

Add to `internal/keep/config_test.go`:
```go
func TestKeepConfig_RemoteActivityLogSinks(t *testing.T) {
    t.Run("valid http sink config with defaults", func(t *testing.T) {
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
  sink: "http"
  http:
    url: "https://splunk.internal:8088/services/collector/raw"
    encoding: "json_array"
    auth:
      type: "splunk"
      token: "static-token-123"
    headers:
      X-Test: "custom"
`
        tmp, err := os.CreateTemp("", "keep-remote-*.yaml")
        if err != nil {
            t.Fatalf("temp: %v", err)
        }
        defer os.Remove(tmp.Name())
        tmp.Write([]byte(yamlConfig))
        tmp.Close()

        cfg, _, err := LoadConfig(context.Background(), tmp.Name())
        if err != nil {
            t.Fatalf("load failed: %v", err)
        }
        act := cfg.MCPActivityLog
        if act.Sink != "http" {
            t.Errorf("expected sink http, got %q", act.Sink)
        }
        if act.HTTP.URL != "https://splunk.internal:8088/services/collector/raw" {
            t.Errorf("unexpected URL: %q", act.HTTP.URL)
        }
        if act.HTTP.Encoding != "json_array" {
            t.Errorf("expected encoding json_array, got %q", act.HTTP.Encoding)
        }
        if act.HTTP.Auth.Type != "splunk" || act.HTTP.Auth.Token != "static-token-123" {
            t.Errorf("unexpected auth: %+v", act.HTTP.Auth)
        }
        if act.HTTP.BatchSize != 100 || act.HTTP.MaxQueuedBatches != 10 || act.HTTP.FlushIntervalMS != 1000 {
            t.Errorf("unexpected http defaults: %+v", act.HTTP)
        }
    })

    t.Run("validation rejections", func(t *testing.T) {
        cases := []struct {
            name        string
            mutate      func(c *MCPActivityLogConfig)
            errContains string
        }{
            {
                name: "invalid sink type",
                mutate: func(c *MCPActivityLogConfig) {
                    c.Sink = "invalid_sink"
                },
                errContains: "unknown sink type",
            },
            {
                name: "missing http url",
                mutate: func(c *MCPActivityLogConfig) {
                    c.Sink = "http"
                    c.HTTP.URL = ""
                },
                errContains: "http url is required",
            },
            {
                name: "invalid http encoding",
                mutate: func(c *MCPActivityLogConfig) {
                    c.Sink = "http"
                    c.HTTP.URL = "https://example.com"
                    c.HTTP.Encoding = "xml"
                },
                errContains: "invalid encoding",
            },
            {
                name: "invalid auth type",
                mutate: func(c *MCPActivityLogConfig) {
                    c.Sink = "http"
                    c.HTTP.URL = "https://example.com"
                    c.HTTP.Auth.Type = "oauth1"
                },
                errContains: "unsupported auth type",
            },
            {
                name: "missing auth token when type specified",
                mutate: func(c *MCPActivityLogConfig) {
                    c.Sink = "http"
                    c.HTTP.URL = "https://example.com"
                    c.HTTP.Auth.Type = "bearer"
                    c.HTTP.Auth.Token = ""
                },
                errContains: "auth token required",
            },
            {
                name: "invalid batch size",
                mutate: func(c *MCPActivityLogConfig) {
                    c.Sink = "http"
                    c.HTTP.URL = "https://example.com"
                    c.HTTP.BatchSize = 0
                },
                errContains: "batch_size must be > 0",
            },
        }

        for _, tc := range cases {
            t.Run(tc.name, func(t *testing.T) {
                c := DefaultMCPActivityLogConfig()
                c.Enabled = true
                tc.mutate(&c)
                err := c.Validate()
                if err == nil || !strings.Contains(err.Error(), tc.errContains) {
                    t.Errorf("expected error containing %q, got: %v", tc.errContains, err)
                }
            })
        }
    })
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test -v ./internal/keep -run TestKeepConfig_RemoteActivityLogSinks`
Expected: FAIL (`HTTP` field undefined or `Validate` method missing)

- [ ] **Step 3: Implement remote sink config structs, defaults, and validation**

1. In `internal/shared/config/unified.go`:
   - Define `HTTPActivityAuthConfig`, `ActivityTLSConfig`, `HTTPActivitySinkConfig`, `OTLPActivitySinkConfig`.
   - Add `Sink string`, `HTTP HTTPActivitySinkConfig`, `OTLP OTLPActivitySinkConfig` to `MCPActivityLogConfig`.
   - Implement `ApplyDefaults()`:
     - Default `Sink`: `"file"`
     - HTTP defaults: `Encoding: "ndjson"`, `BatchSize: 100`, `MaxQueuedBatches: 10`, `FlushIntervalMS: 1000`, `TimeoutMS: 5000`, `MaxRetries: 2`, `RetryBackoffMS: 200`, `Auth.Type: "none"`.
     - OTLP defaults: `BatchSize: 100`, `MaxQueuedBatches: 10`, `FlushIntervalMS: 1000`, `TimeoutMS: 5000`, `MaxRetries: 2`, `RetryBackoffMS: 200`, `Auth.Type: "none"`.
   - Implement `Validate() error` validating sink types, URLs, encodings, auth configurations, TLS settings, and buffer capacities.
2. In `internal/keep/config.go`:
   - Invoke `c.MCPActivityLog.Validate()` inside Keep's configuration validation step.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test -v ./internal/keep -run TestKeepConfig_RemoteActivityLogSinks`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/shared/config/unified.go internal/keep/config.go internal/keep/config_test.go
git commit -m "feat(config): add remote sink configuration schemas (http and otlp) with validation"
```

---

### Task 3: HTTPS Batch Sink (`HTTPBatchSink`)

**Files:**
- Create: `internal/keep/activitylog/http_sink.go`
- Create: `internal/keep/activitylog/http_sink_test.go`

**Interfaces:**
- Produces:
  ```go
  type HTTPBatchSink struct { ... }
  func NewHTTPBatchSink(cfg cfgloader.HTTPActivitySinkConfig) (*HTTPBatchSink, error)
  func (s *HTTPBatchSink) Write(line []byte) error
  func (s *HTTPBatchSink) Close() error
  func (s *HTTPBatchSink) Stats() map[string]any
  ```

- [ ] **Step 1: Write comprehensive unit tests for `HTTPBatchSink`**

Create `internal/keep/activitylog/http_sink_test.go`:
- Test 1: `encoding: "ndjson"` produces newline-separated lines with `Content-Type: application/x-ndjson`.
- Test 2: `encoding: "json_array"` produces valid top-level JSON array `[ {...}, {...} ]` with `Content-Type: application/json`.
- Test 3: Auth formatting:
  - `auth.type: "splunk"`, `token: "splunk-token-123"` sets `Authorization: Splunk splunk-token-123`.
  - `auth.type: "bearer"`, `token: "secret-token-xyz"` sets `Authorization: Bearer secret-token-xyz`.
  - `headers: {"X-Custom": "val"}` sets `X-Custom: val`.
- Test 4: Batch threshold flush: enqueue `batch_size` items; assert immediate HTTP POST.
- Test 5: Ticker interval flush: enqueue partial batch; advance time; assert partial flush.
- Test 6: Non-retryable 4xx (401, 408, 429): mock server returns 429; assert immediate batch drop without retries, increments `dropped_batches`.
- Test 7: 503 transient retry: mock server returns 503 twice then 200; assert batch succeeds on 3rd attempt.
- Test 8: Dispatcher queue full: fill `max_queued_batches`; enqueue next batch; assert `Write` does not block, excess batch drops non-blockingly, metric increments.
- Test 9: Shutdown sequence & request cancellation:
  - Enqueue entries and call `Close()`.
  - Verify ticker terminates cleanly before `dispatchCh` closes.
  - Verify in-flight requests abort if timeout expires via root context cancellation without leaking goroutines.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test -v ./internal/keep/activitylog -run TestHTTPBatchSink`
Expected: FAIL (types not defined)

- [ ] **Step 3: Implement `HTTPBatchSink` with race-free shutdown and cancellation**

Create `internal/keep/activitylog/http_sink.go`:
- Struct:
  - `activeBatch [][]byte`, `mu sync.Mutex`
  - `dispatchCh chan [][]byte` (buffer `cfg.MaxQueuedBatches`)
  - `rootCtx context.Context`, `cancelRoot context.CancelFunc`
  - `stopTicker chan struct{}`, `tickerDone chan struct{}`
  - `dispatcherWg sync.WaitGroup`
  - `httpClient *http.Client` (configured with `cfg.TimeoutMS` and optional custom CA cert pool / PEM)
  - `atomic.Int64` metrics: `exportedEntries`, `failedBatches`, `droppedBatches`, `droppedEntries`.
- `Write(line []byte) error`:
  - Under mutex: appends copy of `line` to `activeBatch`.
  - If `len(activeBatch) >= cfg.BatchSize`: detaches batch, sends non-blockingly to `dispatchCh`. If `dispatchCh` is full, increments drop metrics and drops batch immediately.
- Dispatcher loop (`go s.dispatcher()`):
  - Reads batches from `dispatchCh`.
  - Serializes:
    - `"ndjson"`: `bytes.Join(batch, []byte("\n"))` + `\n`
    - `"json_array"`: `[` + `bytes.Join(batch, []byte(","))` + `]`
  - Sets `Content-Type` and resolved auth headers (`Authorization: Bearer ...` or `Authorization: Splunk ...`).
  - Creates child context `reqCtx, reqCancel := context.WithTimeout(s.rootCtx, s.timeout)`.
  - Dispatches `http.NewRequestWithContext(reqCtx, ...)` with retry loop up to `cfg.MaxRetries`:
    - 2xx: return
    - 4xx: drop immediately, log slog error
    - 5xx / timeout: sleep `cfg.RetryBackoffMS`, retry
  - On retry exhaustion: drop batch, increment `droppedBatches`.
- Ticker loop:
  - Runs in background goroutine. Listens on `ticker.C` and `stopTicker`.
  - On tick: detaches partial batch and sends non-blockingly to `dispatchCh`.
  - On `stopTicker`: exits and closes `tickerDone`.
- `Close() error`:
  - **Step 1 (Stop Ticker)**: `close(s.stopTicker)`, wait `<-s.tickerDone`. Guarantees no concurrent writes to `dispatchCh`.
  - **Step 2 (Queue Final Batch)**: Under mutex, detach remaining `activeBatch`. If non-empty, send to `dispatchCh` (or drop if full).
  - **Step 3 (Close Channel)**: `close(s.dispatchCh)`.
  - **Step 4 (Wait with Cancellation)**: Wait for dispatcher with timeout. If deadline expires, call `s.cancelRoot()`, aborting active HTTP request.

- [ ] **Step 4: Run tests to verify all pass**

Run: `go test -v -race ./internal/keep/activitylog -run TestHTTPBatchSink`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/keep/activitylog/http_sink.go internal/keep/activitylog/http_sink_test.go
git commit -m "feat(activitylog): implement HTTPBatchSink with ndjson/json_array encodings and race-free shutdown"
```

---

### Task 4: OpenTelemetry Log Sink (`OTLPSink`)

**Files:**
- Create: `internal/keep/activitylog/otlp_sink.go`
- Create: `internal/keep/activitylog/otlp_sink_test.go`

**Interfaces:**
- Produces:
  ```go
  type OTLPSink struct { ... }
  func NewOTLPSink(cfg cfgloader.OTLPActivitySinkConfig) (*OTLPSink, error)
  func (s *OTLPSink) Write(line []byte) error
  func (s *OTLPSink) Close() error
  func (s *OTLPSink) Stats() map[string]any
  ```

- [ ] **Step 1: Write unit tests for `OTLPSink` field and attribute mapping**

Create `internal/keep/activitylog/otlp_sink_test.go`:
- Test 1: Full structured serialization of batch into standard OTLP JSON `ExportLogsServiceRequest`:
  - `resource.attributes`: `service.name: "portcullis-keep"`.
  - `scope.name`: `"portcullis.activity_log"`.
  - `timeUnixNano`: matches parsed entry timestamp in nanoseconds Unix epoch.
  - `severityNumber` & `severityText`:
    - `9` / `"INFO"` for requests and success responses.
    - `13` / `"WARN"` for escalation pending and denials.
    - `17` / `"ERROR"` for errors and malformed requests.
  - `traceId`: 36-char hyphenated UUID (`550e8400-e29b-41d4-a716-446655440000`) converted to 32-character lowercase hex (`550e8400e29b41d4a716446655440000`).
  - `body`: `{ "stringValue": string(line) }`.
  - `attributes`: contains `event.type`, `mcp.tool_name`, `mcp.server_name`, `user.id`, `mcp.agent.name`, `mcp.agent.version`, `mcp.status`, `mcp.duration_ms`.
- Test 2: Non-hex `trace_id` (e.g. `test-trace-123`) leaves `traceId` blank on `logRecord` and preserves in `attributes: [{ key: "mcp.trace_id", value: { stringValue: "test-trace-123" } }]`.
- Test 3: Export to mock HTTP OTLP collector (`/v1/logs`): receives valid payload and returns 200.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test -v ./internal/keep/activitylog -run TestOTLPSink`
Expected: FAIL (types not defined)

- [ ] **Step 3: Implement `OTLPSink` with structured field mapping**

Create `internal/keep/activitylog/otlp_sink.go`:
- Reuses the batching, single-threaded dispatcher, and race-free shutdown mechanics from `HTTPBatchSink` with an OTLP payload serializer.
- Serializes each batch into `ExportLogsServiceRequest` JSON payload:
  - Extracts timestamp, severity, trace ID, agent, tool, and status from JSON entry.
  - Populates `timeUnixNano`, `severityNumber`, `severityText`.
  - Formats trace ID: if 36-char UUID, strips hyphens to 32-hex; if invalid hex, leaves `traceId: ""` and adds to attributes.
  - Embeds `body: { stringValue: string(line) }`.
  - Populates structured `attributes` array.
- Dispatches HTTP POST to `cfg.Endpoint` with `Content-Type: application/json` and configured auth headers (`Authorization: Bearer <token>` or custom headers).
- Implements `Write(line []byte)` and `Close()`.

- [ ] **Step 4: Run tests to verify all pass**

Run: `go test -v -race ./internal/keep/activitylog -run TestOTLPSink`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/keep/activitylog/otlp_sink.go internal/keep/activitylog/otlp_sink_test.go
git commit -m "feat(activitylog): implement OTLPSink with structured field and attribute mapping"
```

---

### Task 5: Factory Wiring, Keep Integration & Zero-Fallback Verification

**Files:**
- Modify: `internal/keep/activitylog/sink.go`
- Modify: `internal/keep/server.go`
- Create: `internal/keep/server_activity_network_test.go`
- Modify: `docs/roadmap.md`

**Interfaces:**
- Ensures `newSink(cfg)` constructs `HTTPBatchSink` or `OTLPSink` when configured, and guarantees zero file fallback.

- [ ] **Step 1: Write integration tests for remote sinks and zero-fallback policy**

Create `internal/keep/server_activity_network_test.go`:
- Test 1: Start Keep with `sink: "http"`, `encoding: "json_array"`, pointing to mock SIEM server.
  - Execute tool calls through Keep.
  - Assert mock SIEM receives JSON array batch with valid request and response events.
  - Assert zero activity log files exist in temporary workspace directory.
- Test 2: Start Keep with `sink: "otlp"` pointing to mock OTel Collector.
  - Execute tool calls; assert mock OTel Collector receives valid OTLP JSON batch with structured attributes.
  - Assert zero log files created on disk.
- Test 3: Zero-Fallback Verification: Start Keep with `sink: "http"` and an invalid URL or unreachable server.
  - Assert operational error is logged to `slog`.
  - Assert Keep does NOT fall back to creating `/var/log/portcullis/mcp-activity.log` or any local file.
  - Assert tool calls proceed without crashing.

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test -v ./internal/keep -run TestServerActivityNetwork`
Expected: FAIL (`newSink` does not support "http" or "otlp")

- [ ] **Step 3: Update `newSink` factory in `internal/keep/activitylog/sink.go`**

Update `newSink(cfg cfgloader.MCPActivityLogConfig) (ActivitySink, error)`:
```go
switch cfg.Sink {
case "http":
    return NewHTTPBatchSink(cfg.HTTP)
case "otlp":
    return NewOTLPSink(cfg.OTLP)
case "stdout":
    return &stdoutSink{}, nil
case "file", "":
    return newFileSink(cfg)
default:
    return nil, fmt.Errorf("activitylog: unknown sink type %q", cfg.Sink)
}
```
If `newSink` returns an error during Keep startup:
- Log `slog.Error("mcp_activity_log: failed to initialize sink; activity logging disabled", "error", err)`.
- Fall back to a disabled no-op logger (`New(MCPActivityLogConfig{Enabled: false}, nil)`).
- **NEVER fallback to `fileSink`**.

- [ ] **Step 4: Run integration tests to verify all pass**

Run: `go test -v -race ./internal/keep -run TestServerActivityNetwork`
Expected: PASS

- [ ] **Step 5: Run full project test suite**

Run: `go test -v ./...`
Expected: ALL PASS

- [ ] **Step 6: Update roadmap and commit**

Update `docs/roadmap.md` reflecting remote sinks feature completion.
```bash
git add internal/keep/activitylog/sink.go internal/keep/server.go internal/keep/server_activity_network_test.go docs/roadmap.md
git commit -m "feat(keep): wire remote sinks into activity log factory and enforce zero file fallback"
```
