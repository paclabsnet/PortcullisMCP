# Performance Monitoring Implementation Plan

**Goal:** Add OpenTelemetry metrics and Prometheus scrape endpoints to Keep, Guard, and Multi-Tenant Gate, while preserving tracing and excluding Single-Tenant Gate.

**Design:** [Performance Monitoring & Metrics Design Specification](../specs/2026-11-06-performance-monitoring-design.md)

**Tracking:** [Performance Monitoring & Metrics Tracking Document](../tracking/2026-11-06-performance-monitoring-tracking.md)

**Approach:** Implement and test the shared telemetry lifecycle and HTTP instrumentation first, then instrument each component. Verify real Prometheus output, configuration, authorization, and existing behavior before removing the Keep readiness counters.

## Constraints and decision gates

- Keep the design's metric names and units as the **Prometheus wire contract**. OpenTelemetry's exporter may translate instrument names and units; use one naming convention that produces the specified output, and assert actual scrape names, types, labels, and histogram units. Do not append suffixes twice.
- Tracing and metrics are independently configured: omitted or `noop` trace exporter must not disable enabled metrics. Single-Tenant Gate must retain its existing tracing behavior without initializing metrics, regardless of YAML metrics settings.
- Preserve existing endpoint authentication and TLS behavior. The design specifies that Gate's scrape endpoint bypasses session authentication; this does not establish a separate monitoring authentication mechanism. Confirm how the selected listener's existing authentication and network controls apply before rollout, and document the resulting access boundary.
- A custom metrics path must be validated, mounted and normalized consistently, including Gate's bypass rule. Reject collisions with existing routes and invalid paths instead of silently overriding them.
- Resolve the following design/data mismatches before implementing the affected metric. Record the agreed semantics in the design and test them; never invent verdicts or success counts from insufficient information:
  - Keep currently supports `opa` and `noop` policy strategies, not all the proposed `policy_engine` values, and has no PDP decision cache. Define engine labels and the meaning of `cached`; do not conflate principal or tool caches with a PDP decision cache.
  - Keep's `/call` returns an MCP result on allow; a backend failure can occur after an allow. Gate's forwarder converts HTTP responses into errors and does not reliably distinguish every `escalate` from `workflow` response. Define an explicit, backward-compatible way to carry the actual PDP verdict to Gate, or revise that metric's contract. A tool execution result or transport error is not itself a PDP decision.
  - Guard's `ClaimToken` contract treats absent, already claimed, and expired tokens alike; cleanup APIs return no expired counts. Approval handlers also do not expose a distinct rejection transition. Define accurate claim and lifecycle semantics for both memory and Redis stores, including concurrency and expiry; revise labels or extend store contracts if needed rather than fabricate `expired` or `rejected` events.
  - Gate's session store has no count operation; memory entries expire or are evicted and Redis keys expire independently and may be shared by multiple Gate instances. Agree on per-process versus shared-store semantics, TTL and failure behavior before implementing `active_sessions`. A process-local increment/decrement is not an authoritative Redis count.
  - A configured set of tools or backends can change on reload, and previously seen metric series can remain in the SDK. Define and enforce a measurable cardinality budget across reloads, including overflow behavior. Unknown tool names use `unknown` as specified.
- Maintain the current production behavior on telemetry startup failure unless an intentional change is separately approved. Log initialization and shutdown failures explicitly; do not make a failed exporter appear healthy.
- Pull metrics are scraped, not pushed on shutdown. Shutdown releases resources but cannot guarantee delivery of observations that Prometheus has not scraped.

## Task 1: Metrics configuration and telemetry lifecycle

**Files:** `go.mod`, `go.sum`, `internal/telemetry/provider.go`, `internal/telemetry/provider_test.go`, `internal/shared/config/unified.go`, component config tests, and `cmd/portcullis-{keep,guard,gate}/main.go`.

- [ ] Add compatible OpenTelemetry metric SDK, Prometheus exporter, and Prometheus client dependencies using the Go toolchain; preserve alignment with the existing OpenTelemetry versions.
- [ ] Extend `telemetry.Config` with metrics enablement and path. Distinguish an omitted `enabled` from explicit `false` (including an omitted `metrics` block); default on for Keep, Guard, and Multi-Tenant Gate, and force off for Single-Tenant Gate. Validate the path and collisions at configuration/startup.
- [ ] Create a metric provider and Prometheus reader/registry independently from the tracer provider. Keep existing W3C propagation and configured trace exporter behavior. Use a matching registry and handler; avoid duplicate global registry registration across repeated setup or tests. Provide a no-op meter when metrics are disabled.
- [ ] Wire Guard startup and shutdown, and adapt Keep/Gate startup so the runtime receives the correct mode, handler, and meter. Prefer explicit dependency injection into servers and instrumentation; if retaining the design's global API, define ownership and prevent cross-test/provider leakage. Avoid initializing a metric provider in single-tenant mode.
- [ ] Make setup failure cleanup and shutdown cover both providers, including partial initialization and error reporting. Ensure shutdown actually runs on normal and error exits; avoid `os.Exit` bypassing deferred cleanup.
- [ ] Add table-driven tests covering omitted, true, and false metrics config; custom and conflicting paths; each component/tenancy mode; trace `noop` with metrics enabled; active tracing with metrics disabled; setup twice; and shutdown. Test startup wiring using the existing command test seams.

**Verify:** `go test ./internal/telemetry ./internal/shared/config ./cmd/portcullis-keep ./cmd/portcullis-guard ./cmd/portcullis-gate`

## Task 2: Shared HTTP instrumentation and scrape routing

**Files:** `internal/shared/middleware/` (new metrics middleware and tests), `internal/keep/server.go`, `internal/guard/server.go`, `internal/gate/mcp_http.go`, and corresponding server tests.

- [ ] Add reusable HTTP request count and duration instrumentation with component-specific names, labels, and listener labels for Guard. Normalize methods and paths to bounded values; never label raw paths, query strings, tokens, or request data. Define a bounded `other` for unknown paths/methods and an explicit rule for all status codes.
- [ ] Use actual route patterns. Keep currently serves `/call`, `/authorize`, `/tools`, `/config/{resource}`, `/oauth/callback`, `/healthz`, and `/readyz`; the design's `/mcp` is not its current API. Keep route labels in sync with implemented routes and document any design correction.
- [ ] Wrap response writers without breaking MCP streaming and optional HTTP capabilities used by the SDK (including flushing and unwrapping). Count implicit status 200, explicit errors, and authentication failures exactly once; account for requests that outlive the handler such as streams. Select and test sensible histogram bucket boundaries in seconds.
- [ ] Mount the configured scrape handler only when metrics are enabled. Keep it subject to the existing configured auth middleware; mount it on both Guard listeners as designed; bypass Gate session auth only for the configured GET scrape path and keep other paths protected. Preserve listener-level TLS and auth. Confirm the Guard listener exposure choice with deployment owners as part of the decision gate.
- [ ] Test actual HTTP behavior: enabled/disabled paths, custom paths, 404/405 behavior, auth success and failure, status and normalized labels, dynamic paths, duplicate registration, and streaming/flushing. Ensure repeated scrapes do not expose request data or create new labels.

**Verify:** `go test ./internal/shared/middleware ./internal/keep ./internal/guard ./internal/gate`

## Task 3: Keep PDP, backend, and activity-log metrics

**Files:** `internal/keep/server.go`, `internal/keep/pdp.go`, `internal/keep/router.go`, `internal/keep/activitylog/`, their tests, and the Keep configuration examples.

- [ ] After resolving PDP label semantics, instrument both `/call` and `/authorize` evaluations at a common boundary so each evaluation, error, and duration is recorded exactly once, including mocked PDPs. Record the PDP decision independently of subsequent backend or workflow failures.
- [ ] Instrument `Router.CallTool` and connection failures for configured backends. Classify timeout versus other errors consistently and bound backend labels across configuration reloads. Count MCP tool error results according to a documented definition rather than only Go errors.
- [ ] Expose activity logger's dropped-buffer and remote sink delivery statistics as cumulative observable counters. Register callbacks once and unregister them during shutdown/reconfiguration. Preserve atomicity and monotonic behavior during reload; document reset behavior on process restart.
- [ ] Implement meaningful successful-delivery counts for `file` and `stdout`, whose existing sinks do not implement `StatsSink`; retain existing remote sink semantics for exported entries and dropped batches/entries. Do not report queued remote events as delivered. Respect the legacy `file: stdout` configuration when choosing the sink label.
- [ ] Remove `activity_log` from `/readyz` only after all replacement counters work. Preserve status, tools, signer fields and failure status; document the breaking response change and migration.
- [ ] Add table-driven tests for allow, deny, escalate, workflow and errors on both authorization paths; backend success, timeout and connection failure; each sink type, dropped batches and entries, callback lifecycle and repeated scrapes; readiness success/failure and absence of `activity_log`.

**Verify:** `go test ./internal/keep ./internal/keep/activitylog`

## Task 4: Guard token and lifecycle metrics

**Files:** `internal/guard/server.go`, `internal/guard/store.go`, `internal/guard/memstore.go`, `internal/guard/redis_store.go`, and Guard tests.

- [ ] Resolve the Guard lifecycle decision gate first. Define precisely whether a creation is counted at signing or after persistence, what constitutes a failed creation, and which claim/pending outcomes can be observed consistently by memory and Redis stores. Update the design if its current enum cannot be produced without changing store behavior.
- [ ] Instrument UI approvals and direct deposits, token claims, and pending lifecycle transitions at the agreed boundaries. Preserve the pending request JTI as the issued token JTI; do not label identities, JTI, token contents, or scope.
- [ ] If store contracts must change for accurate expiry/rejection accounting, update all implementations and test doubles together, including atomic claims, concurrent cleanup, Redis TTL expiry, error paths, and no duplicate counts. Do not change API responses or persistence semantics solely to produce metrics without approval.
- [ ] Test successful and failed signing/persistence, successful claims and indistinguishable missing/expired states, cleanup behavior, both listeners and storage backends, and scrape labels. Verify existing approval and claim behavior remains unchanged.

**Verify:** `go test ./internal/guard`

## Task 5: Multi-Tenant Gate metrics

**Files:** `internal/gate/server.go`, `internal/gate/forwarder.go`, `internal/gate/mcp_http.go`, `internal/gate/escalation_manager.go`, `internal/gate/session_store.go`, memory/Redis store implementations, and Gate tests.

- [ ] Resolve verdict transport and active-session semantics before implementing those instruments. Where a protocol change is required, specify mixed-version Gate/Keep behavior and backward compatibility; do not infer an allow from a successful transport alone or an error from a backend failure.
- [ ] Record tool-call count and end-to-end duration exactly once, distinguish source and actual PDP decision, and count escalation claim outcomes at the operation boundary. Use `unknown` for unrecognized tool names and enforce the agreed cardinality budget across tool refreshes.
- [ ] Implement the agreed active-session measurement for memory and Redis, including initialization, expiry, eviction, deletion, restart, clustered access, and store failure behavior. Avoid counting a shared Redis total once per Gate instance in a way that causes aggregation to double-count it.
- [ ] Instrument only the paths available in Multi-Tenant Gate; test any fast-path or escalation paths that are actually enabled by tenancy capabilities rather than assuming they are enabled. Keep Single-Tenant Gate's tool handling and tracing unchanged and verify no metrics registry/listener is initialized there.
- [ ] Test forwarded allow, deny, escalation/workflow and backend failure separately, claim outcomes, session lifecycle, mode isolation, configured scrape-path authentication behavior, bounded labels, and multiple instances sharing Redis where applicable.

**Verify:** `go test ./internal/gate`

## Task 6: Documentation and end-to-end verification

**Files:** `ARCHITECTURE.md`, `README.md` or appropriate operator guide, `config/` examples, and the design/tracking documents if decisions changed.

- [ ] Document configuration defaults, `enabled: false`, custom paths, independent tracing/metrics settings, listener and auth/TLS requirements, label/cardinality budget, histogram units, per-instance versus shared metric semantics, and the Keep `/readyz` migration. Include a realistic Prometheus scrape configuration that matches each listener's authentication.
- [ ] Add integration coverage that starts the actual HTTP servers, performs representative operations, and scrapes with Prometheus-compatible parsing. Assert exact metric names, types, labels, counter deltas, histogram buckets in seconds, and monotonic values across multiple scrapes. Test a non-default path and disabled endpoint.
- [ ] Exercise unauthorized and authorized scraping under configured auth, repeated setup/shutdown, trace `noop` with metrics enabled, a remote activity sink failure, unrecognized tool names, and a single-tenant Gate. Verify no sensitive or unbounded labels appear.
- [ ] Run `go test ./...`, `go build ./cmd/...`, and `golangci-lint run` when the existing lint tool is available. Run targeted race tests for telemetry callbacks and concurrent session/store operations where supported: `go test -race ./internal/telemetry ./internal/keep/activitylog ./internal/guard ./internal/gate`.
- [ ] Update the tracking document to reflect implementation and verification results; distinguish tests actually run from tests deferred.

## Completion criteria

- All three intended components expose their configured scrape endpoint with the documented access policy; Single-Tenant Gate does not initialize or expose metrics.
- The design's accepted wire metrics are observable and accurate, including failure paths, with bounded label sets and no sensitive values.
- Existing tracing and MCP behavior remain intact; Keep readiness no longer contains activity delivery counters.
- Decision gates and any approved design deviations are recorded, documentation is current, and verification results are reported.
