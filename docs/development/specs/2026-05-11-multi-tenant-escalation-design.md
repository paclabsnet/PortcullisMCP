# Multi-tenant Escalation Support Plan

## Objective
Enable the 'escalate' (human-in-the-loop approval) functionality in multi-tenant environments by moving state tracking to Redis. Decouple the escalation logic from the concept of "tenancy mode", making it solely dependent on a new top-level `Escalation` configuration. This unifies how escalations are handled and introduces scoping (by session or credential fingerprint) to both multi-tenant and single-tenant deployments, while simplifying the system by removing background polling.

## Key Files & Context
- `internal/gate/config.go`
- `internal/gate/config_test.go`
- `internal/gate/mcp_http.go`
- `internal/gate/tenancy.go`
- `internal/gate/multi_tenant_provider.go`
- `internal/gate/single_tenant.go`
- `internal/gate/server.go`
- `internal/gate/guardclient.go`
- `internal/gate/escalation_manager.go`
- `internal/gate/tokenstore.go`
- `internal/gate/redis_pending_store.go` (New)
- `internal/gate/redis_token_store.go` (New)

## Proposed Solution

1. **Top-Level Escalation Strategy**: Introduce a new top-level string configuration `cfg.Escalation` (alongside `tenancy` and `server`) to dictate how approvals are tracked and whether escalation is enabled at all. Detailed settings (like token store paths) will remain in `cfg.Responsibility.Escalation`.
   - `disabled`: Escalation is completely disabled. Any `EscalationPendingError` is immediately intercepted and converted to a Deny (with SIEM logging). This applies universally, regardless of tenancy.
   - `session` (default): 
     - **Multi-tenant**: Approvals are bound to the specific `Mcp-Session-Id` header provided by the Agent.
     - **Single-tenant**: Approvals are bound to a constant session ID (e.g., `"0"`). Approvals survive Agent restarts and logins because the session ID never changes.
   - `fingerprint`: 
     - **Multi-tenant & Single-tenant**: Approvals are bound to the hash of the raw authentication token. If no authentication token is present (e.g., in single-tenant mode using the 'os' identity strategy), it falls back to using the UserID from the identity configuration as the fingerprint. Approvals are shared across all Agents using the exact same token/user, but are invalidated immediately upon logging in again (as the token/expiration changes).
2. **Remove Background Polling**: Because proactive grants are fundamentally incompatible with ephemeral session IDs and hashed token fingerprints, background polling is conceptually broken in this new model. We will remove `StartPolling` and `ListUnclaimedTokens` entirely. The system will rely 100% on the "Lazy Claim" (claiming the token synchronously when the Agent retries the tool call).
3. **Decouple Tenancy from Escalation**: 
   - Remove `MapPolicyError` from the `TenancyProvider` interface entirely. The interception of escalations is no longer a "multi-tenant" feature; it is a "Escalation=disabled" feature.
   - Remove `AllowHumanInLoop` and `AllowGuardPeer` from `Capabilities`. These are now dictated by `cfg.Escalation != "disabled"`.
4. **Keep Management Console Disabled in Multi-Tenant (Phase 1)**:
  - The Gate management console/API remains disabled in multi-tenant mode for now.
  - No multi-tenant token browsing/injection UX is introduced in this phase.
  - Scoped token store changes are implemented for request-time enforcement only.
5. **Context-Aware Storage Interfaces**: Update `EscalationTokenStore` and `PendingEscalationStore` interfaces to require `context.Context` on all methods so they can extract the Session ID or Fingerprint to generate the appropriate partition key.
6. **Redis-Backed State**: Implement `RedisPendingStore` and `RedisTokenStore` to replace the memory/file-backed stores when `cfg.Operations.Storage.Backend == "redis"`.

## Implementation Steps

### 1. Configuration & Context Updates
- In `internal/gate/config.go`, add a top-level `Escalation string` to the `Config` struct (defaults to "session"). Add validation for "session", "fingerprint", or "disabled". Additionally, implement a fail-fast validation check: if `Escalation` is "session" or "fingerprint", `cfg.Peers.Guard` MUST be configured.
- Update `validateMultiTenant` in `internal/gate/config.go`:
  - Explicitly allow Guard. **Crucially, modify or remove Rule 5** ("Guard must not be configured in multi-tenant mode") so that it only rejects Guard configuration if `Escalation` is set to "disabled".
  - **Add a new validation rule:** If `Escalation` is not "disabled", the configured storage backend (`Operations.Storage.Backend`) MUST be "redis". A file-based or memory-based `TokenStore` is forbidden in multi-tenant mode.
- Keep the `EscalationConfig` struct inside `ResponsibilityConfig` to hold the detailed settings (`token_store`, `no_escalation_marker`, etc.), but **remove its boolean `Enabled` field** (as the top-level string now controls enablement) and **remove the `Strategy` field** ("proactive"/"user-driven"). 
- **Standardize on Proactive:** Remove `isProactive()` from `Gate` and update `buildEscalationMessage` and `EscalationManager.StorePending` to always behave proactively (i.e., unconditionally push the pending JWT to Guard and return the short `?jti=` URL). Because `RegisterPending` is now a hard runtime dependency, update the failure mode in `StorePending` and the policy error mapper: if Guard is unreachable, it MUST return a clear error message to the agent explaining that the authorization workflow system is unavailable (rather than a generic "denied" or "internal error").
- Update configuration loading tests in `config_test.go` and update example/demo YAML files to reflect the new top-level `escalation` key, and the removal of the `enabled` and `strategy` fields.
- Preserve the existing multi-tenant restriction that management UI/API is not configured or started.
- In `internal/gate/mcp_http.go`, ensure the calculated `CredentialFingerprint` is injected into the request context for HTTP requests. For stdio requests, update `internal/gate/server.go` (`handleToolCall`) to compute the fingerprint directly from the current `UserIdentity.RawToken` (falling back to `UserID` if empty) and inject it into the context. This avoids unnecessarily changing the `TenancyProvider.Authenticate` interface signature.

### 2. TenancyProvider Refactor
- Remove `MapPolicyError` from `TenancyProvider`.
- Remove `AllowHumanInLoop` and `AllowGuardPeer` from the `Capabilities` struct.
- In `internal/gate/server.go` (`policyErrToResult`), implement the logic: If `cfg.Escalation == "disabled"`, intercept `EscalationPendingError`, emit a SIEM log, and return the `NoEscalationMarker` as a deny. Otherwise, process the escalation normally.

### 3. Remove Background Polling
- In `internal/gate/server.go`, remove the `GuardSource` interface's `ListUnclaimedTokens` method.
- Update `internal/gate/guardclient.go` to remove the implementation of `ListUnclaimedTokens`.
- In `internal/gate/escalation_manager.go`, remove `StartPolling`, `pollGuardWorker`, and `claimAllUnclaimedTokens`.
- In `internal/gate/server.go` (`Run`), remove the block that calls `g.escalationMgr.StartPolling(ctx)`.
- In `internal/guard/store.go`, remove `ListUnclaimed` from the `UnclaimedStore` interface. Update `internal/guard/redis_store.go` and `internal/guard/memstore.go` to remove their implementations.
- In `internal/guard/server.go`, remove the `handleTokenUnclaimedList` method and the `GET /token/unclaimed/list` route registration. Remove corresponding tests in `internal/guard/server_token_test.go`.

### 4. Context-Aware Stores & Key Generation
- Update `internal/gate/tokenstore.go` interfaces (`EscalationTokenStore`, `PendingEscalationStore`) to pass `context.Context` to all methods (e.g., `All(ctx)`, `Get(ctx, key)`, `Store(ctx, key, val)`).
- Implement a helper function `resolveStoragePrefix(ctx context.Context, scope string, identity IdentitySource, isMultiTenant bool) string`.
  - If scope is `session`: returns `SessionIDFromContext(ctx)` (if single-tenant, it returns `"0"` or handles the empty session string appropriately).
  - If scope is `fingerprint`: returns the fingerprint from context. If the fingerprint is empty, it queries the `IdentitySource` and uses the user ID as the fingerprint fallback.
- **Prevent Key Collisions:** Ensure that `EscalationManager` (or the store implementation) prepends the resolved `scope_prefix` to the keys used in `PendingEscalationStore` (e.g., changing the key from `serverName + "/" + toolName` to `<scope_prefix>:<serverName>/<toolName>`). This prevents cross-session overwrites when two different users escalate the same tool simultaneously.
- Update the existing local `TokenStore` and `InMemoryPendingStore` to use this prefix when storing/retrieving values, ensuring single-tenant mode also respects the scope boundaries.

### 5. Redis Store Implementations
- Create `internal/gate/redis_pending_store.go` and `internal/gate/redis_token_store.go`.
- These implementations will use `resolveStoragePrefix` to partition keys in Redis (e.g., `portcullis:gate:escalation:<prefix>:<jti>`).
- Wire these into `Gate.New` when the Redis backend is configured.

### 6. Lazy Claim Telemetry & Logging
- **Surface HTTP Status:** Modify `internal/gate/guardclient.go` to surface the HTTP status code from Guard. Introduce a custom error type (e.g., `GuardAPIError{StatusCode int, Err error}`) returned by `GuardClient.ClaimToken` when an HTTP error occurs, or modify the return signature if appropriate, so the caller can extract the status code.
- In `internal/gate/escalation_manager.go` (specifically within the `CollectTokens` or lazy claim logic), add structured logging to record the outcome of the synchronous token claim attempt against Guard.
- The log entry MUST include the following fields to provide a canonical record of the lazy claim event:
  - `phase`: "lazy_claim"
  - `jti`: The ID of the token being claimed.
  - `trace_id`: The trace ID associated with the request.
  - `scope_type`: The configured storage scope ("session" or "fingerprint").
  - `scope_key_hash`: A masked or hashed version of the resolved storage prefix/key to aid debugging without leaking raw tokens. **Implementation Note:** The implementer must explicitly document the chosen hashing algorithm and encoding (e.g., "first 8 hex chars of SHA-256 of the raw prefix") in a code comment to ensure the format does not drift between versions and remains useful for log correlation.
  - `guard_status_code`: The HTTP status code returned by Guard (extracted via the new `GuardAPIError` or updated return signature; 200/404 for success/not found, otherwise the error code).
  - `outcome`: "success", "not_found", or "error".
  - `error_class`: A categorization of the error if `outcome` is "error" (e.g., "network_timeout", "unauthorized").
  - `elapsed_ms`: The duration of the Guard API call.

## Verification & Testing
- **Proactive Dependency Tests**: Add a test case to ensure that when `EscalationManager.StorePending` fails to push the request to Guard (e.g., network error or 503), the Agent correctly receives the specific error message explaining that the authorization workflow system is unavailable.
- **Unit Tests**: Test the key prefix generation logic (`resolveStoragePrefix`) for all combinations of scope and tenancy.
- **Single-Tenant Scope Tests**: Verify that in single-tenant mode with `fingerprint` scope, changing the token clears access to previous approvals. Verify `session` scope preserves them.
- **Multi-Tenant Integration**: Verify that `disabled` scope emits a SIEM log and denies the request. Verify `session` scope successfully returns the Guard URL and allows the subsequent retry to succeed.
- **Tenancy Decoupling**: Ensure `policyErrToResult` correctly handles errors without relying on the provider interface.
- **Configuration Tests**: Ensure all existing config tests pass with the new top-level `escalation` field and the modified `responsibility.escalation` block.