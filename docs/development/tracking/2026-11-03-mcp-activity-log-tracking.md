# MCP Activity Log Tracking Document

**Date:** 2026-11-03
**Status:** Design Written / Ready for Review

## Documents
- **Core Activity Log Design Spec:** `docs/development/specs/2026-11-03-mcp-activity-log-design.md`
- **Core Activity Log Implementation Plan:** `docs/development/plans/2026-11-03-mcp-activity-log.md`
- **Remote Sinks Design Spec (HTTPS & OTLP):** `docs/development/specs/2026-11-03-remote-activity-log-sinks-design.md`

## Completed Steps
- [x] Initial roadmap review and selection of Phase 3 "MCP Activity Log" feature.
- [x] Architectural design of core activity log (agent discovery, correlated JSON-lines, synthetic denial/escalation records, rotation, truncation).
- [x] Specification and implementation plan written, reviewed, and approved for core activity log.
- [x] Branch `feature/remote_activity_log_sinks` created by user.
- [x] Architectural design of remote sinks to eliminate local disk storage for privacy/compliance:
  - Top-level sink-agnostic policy fields (`enabled`, `sink`, `buffer_size`, `truncate_payloads`, `max_payload_bytes`, `include_pdp_decision`).
  - `HTTPBatchSink`: Newline-delimited JSON batches over TLS (Splunk HEC raw, Datadog Logs API, Elastic, webhooks).
  - `OTLPSink`: Standard OTLP/HTTP `/v1/logs` schema for OpenTelemetry Collectors with 32-character hex trace ID conversion.
  - Dedicated single-threaded sequential dispatcher preserving FIFO delivery and preventing unbounded goroutines.
  - Non-blocking proxy hot-path with bounded in-memory buffer (best-effort delivery with atomic drop metrics).
  - Custom TLS CA certs and header authentication.
- [x] Remote sinks design specification written and refined: `docs/development/specs/2026-11-03-remote-activity-log-sinks-design.md`.

## Current State
Remote activity log sinks design document is written, aligned with top-level policies, and ready for user review.
