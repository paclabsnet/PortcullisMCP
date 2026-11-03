# MCP Activity Log Tracking Document

**Date:** 2026-11-03
**Status:** Design & Plan Approved / Ready for Implementation

## Documents
- **Design Spec:** `docs/development/specs/2026-11-03-mcp-activity-log-design.md`
- **Implementation Plan:** `docs/development/plans/2026-11-03-mcp-activity-log.md`

## Completed Steps
- [x] Initial roadmap review and selection of Phase 3 "MCP Activity Log" feature.
- [x] Architectural design:
  - Agent discovery via MCP `initialize` handshake (`clientInfo`).
  - Correlated request and response JSON-lines records sharing `trace_id` and `session_id`.
  - Synthetic terminal response records emitted on PDP denial, escalation pending, PDP infrastructure error, identity normalization failure, and hidden tool name rejection.
  - Tool-level error classification (`err == nil` with `result.IsError == true` logged with `status: "error"`, error details, and retained full `result` object).
  - Multi-tenant session ID response header interception to bind `AgentInfo` to SDK-assigned `Mcp-Session-Id`.
  - Extension of `SessionStore` with `SaveAgentInfo` and `GetAgentInfo` for memory and Redis stores.
  - Strict isolation of `AgentInfo` from `state []byte` so credential fingerprints (`bytes.Equal(st, fp)`) are never touched or modified.
  - Pre-enqueue truncation and body preservation via `cappedTeeReader`.
  - Lock-free atomic admission and panic-free channel lifecycle during shutdown.
  - Full forensic payload fidelity preserved when `truncate_payloads: false`.
  - Multi-step escalation correlation across distinct trace IDs via `escalation_jti`.
  - Explicit disabled-state safe path (`s.activityLog` non-nil no-op, `Enabled() bool` check, nil-safe methods, and zero body wrapping when disabled).
  - Explicit migration of legacy `decision_log` callers, test fixtures, error mapper, forwarder, and config schemas across Gate and Keep.
  - Presence-aware pointer booleans (`*bool`) for `Compress` and `IncludePDPDecision` with `IsCompressed()` / `ShouldIncludePDPDecision()` helpers, defaulting to `false` when omitted (`compress: false`, `include_pdp_decision: false`), while preserving explicit `true` values.
  - Valid configuration tests using `keep.LoadConfig` and actual server endpoints structure instead of obsolete schemas.
- [x] Design specification written and updated.
- [x] Implementation plan written with TDD tasks and unit/integration tests.

## Current State
Design and implementation plan documents are complete, fully validated, and finalized.
