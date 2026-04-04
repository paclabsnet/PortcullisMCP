# Plan: Enterprise Polish & Roadmap Completion (Revised)

Enhance Portcullis for Enterprise Architect review by improving visibility, consistency, and resolving a key roadmap technical debt.

## Objective
1. **Visibility**: Enrich `portcullis_status` tool with User Identity details.
2. **Roadmap**: Fix `vault://` secret resolution for `map[string]string` fields (e.g. headers).
3. **Consistency**: Align terminology by renaming `requires_approval` to `escalate` in Agent messages.

## Key Files & Context
- `internal/gate/degraded.go`: `buildStatusReport` implementation.
- `internal/gate/status_test.go`: Tests for `buildStatusReport`.
- `internal/shared/secrets/resolver.go`: Secret URI resolution logic and allowlist checks.
- `internal/shared/secrets/resolver_test.go`: Tests for secret resolution.
- `internal/gate/config.go`: Gate configuration structures.
- `internal/gate/server.go`: Gate tool call handling.

## Implementation Steps

### Phase 1: Enrich `portcullis_status` with Identity
- **File**: `internal/gate/degraded.go`
- **Action**: Update `buildStatusReport(ctx context.Context)`:
    - Call `g.identity.Get(ctx)` to retrieve the current `shared.UserIdentity`.
    - Format and append identity info (User ID, Display Name, Groups) to the status message.
- **File**: `internal/gate/status_test.go`
- **Action**: Update unit tests to verify the presence of identity info in the report.

### Phase 2: Prefix-based Secret Allowlisting
- **File**: `internal/shared/secrets/resolver.go`
- **Action**: Update `ResolveConfig` and `walkValue` logic:
    - Implement a helper `isAllowed(path string, allowset map[string]bool) bool` that checks if the full path or any parent dotted path (e.g., `a.b` for `a.b.c`) is in the allowlist.
    - Use `isAllowed` in `resolveWithSource` for restricted scheme checks.
- **File**: `internal/shared/secrets/resolver_test.go`
- **Action**: Add `TestResolveConfig_MapWithParentAllowlist` to verify map keys are resolved if the map field itself is allowlisted.

### Phase 3: Terminology Alignment (`requires_approval` -> `escalate`)
- **File**: `internal/gate/config.go`
- **Action**: 
    - Rename `AgentInstructionsConfig.RequireApproval` field to `Escalate`.
    - Update `AgentInteractionConfig.Validate()` to map the deprecated `RequireApproval` to `Escalate` for backward compatibility.
- **File**: `internal/gate/server.go`
- **Action**: Update `buildEscalationMessage` to use the new `Escalate` field for instructions.
- **Files**: `config/*.yaml` and `deploy/docker-sandbox/*.yaml`
- **Action**: Update example and demo configs to use `escalate` instead of `requires_approval`.

## Verification & Testing
1. **Unit Tests**:
    - Run `go test ./internal/gate/...`
    - Run `go test ./internal/shared/secrets/...`
2. **Manual Verification**:
    - Start the demo stack.
    - Run `portcullis_status` from an agent and verify identity display.
    - Test `vault://` or `envvar://` resolution for a custom header in `decision_logs.headers` by allowlisting `operations.storage.config.decision_log.headers`.
