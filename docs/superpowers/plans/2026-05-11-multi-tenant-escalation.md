# Multi-tenant Escalation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Enable the 'escalate' functionality in multi-tenant environments by moving state tracking to Redis, decoupling escalation from tenancy mode, and standardizing on a request-driven "Lazy Claim" model.

**Architecture:** This builds a unified escalation system where enablement and scoping (`session`, `fingerprint`, `disabled`) are controlled by a top-level configuration. It replaces background polling with a synchronous "Lazy Claim" during Agent retries, uses context-aware partitioning to isolate state in shared storage (Redis), and mandates proactive escalation registrations.

**Tech Stack:** Go, Redis, MCP (Model Context Protocol).

---

### Task 1: Configuration Schema & Validation Updates

**Files:**
- Modify: `internal/gate/config.go`
- Modify: `internal/gate/config_test.go`

- [x] **Step 1: Add top-level Escalation field and update EscalationConfig**
Modify `Config` struct to add `Escalation string` (tags: `yaml:"escalation"`).
Modify `EscalationConfig` to remove `Enabled bool` and `Strategy string`.

- [x] **Step 2: Update validateMultiTenant rules**
Remove Rule 5 (blanket Guard rejection).
Add logic to Rule 5: Reject Guard configuration ONLY if `Escalation == "disabled"`.
Add new Rule: If `Escalation != "disabled"`, `Operations.Storage.Backend` must be `"redis"`.

- [x] **Step 3: Add fail-fast validation for Guard Peer**
In `Validate()`, ensure if `Escalation` is "session" or "fingerprint", `cfg.Peers.Guard` has at least one endpoint configured.

- [x] **Step 4: Update config tests**
Update `TestConfig_Validate` and `TestConfig_ValidateMultiTenant` in `config_test.go` to reflect the new schema and validation rules.

---

### Task 2: Context Enhancement & Fingerprint Injection

**Files:**
- Modify: `internal/gate/mcp_http.go`
- Modify: `internal/gate/server.go`

- [x] **Step 1: Inject fingerprint in MCP HTTP middleware**
In `ServeHTTP`, calculate the SHA-256 hash of the `Authorization` header's token (if present) and store it in the context as `credentialFingerprintKey`.

- [x] **Step 2: Inject fingerprint in handleToolCall for stdio**
In `handleToolCall`, extract `UserIdentity` from context. Compute the hash of `UserIdentity.RawToken` (falling back to `UserIdentity.UserID` if empty) and inject it into the context for the duration of the tool call.

---

### Task 3: TenancyProvider & Capability Refactor

**Files:**
- Modify: `internal/gate/tenancy.go`
- Modify: `internal/gate/multi_tenant_provider.go`
- Modify: `internal/gate/single_tenant.go`
- Modify: `internal/gate/server.go`

- [x] **Step 1: Remove MapPolicyError from TenancyProvider**
Delete `MapPolicyError` method from the `TenancyProvider` interface and both implementations.

- [x] **Step 2: Remove Escalation capabilities**
Remove `AllowHumanInLoop` and `AllowGuardPeer` from `Capabilities` struct and all constructors.

- [x] **Step 3: Centralize escalation interception in server.go**
In `policyErrToResult`, check `cfg.Escalation == "disabled"`. If true, intercept `EscalationPendingError`, log to SIEM, and return the `NoEscalationMarker`.

---

### Task 4: Remove Background Polling (Gate)

**Files:**
- Modify: `internal/gate/server.go`
- Modify: `internal/gate/guardclient.go`
- Modify: `internal/gate/escalation_manager.go`

- [x] **Step 1: Remove ListUnclaimedTokens from GuardSource**
Delete the method from the interface and the `GuardClient` implementation.

- [x] **Step 2: Delete polling logic in EscalationManager**
Remove `StartPolling`, `pollGuardWorker`, and `claimAllUnclaimedTokens` methods. Delete any associated tickers or channels.

- [x] **Step 3: Cleanup Gate startup**
In `Gate.Run`, remove the goroutine that starts the escalation manager polling.

---

### Task 5: Remove Polling Endpoint (Guard)

**Files:**
- Modify: `internal/guard/store.go`
- Modify: `internal/guard/server.go`
- Modify: `internal/guard/memstore.go`
- Modify: `internal/guard/redis_store.go`

- [x] **Step 1: Remove ListUnclaimed from Guard stores**
Remove the method from `UnclaimedStore` interface and implementations in `memstore.go` and `redis_store.go`.

- [x] **Step 2: Remove Guard list endpoint**
Remove `handleTokenUnclaimedList` from `server.go` and its registration in the router. Delete associated tests in `server_token_test.go`.

---

### Task 6: Context-Aware Storage Interfaces

**Files:**
- Modify: `internal/gate/tokenstore.go`
- Modify: `internal/gate/escalation_manager.go`

- [x] **Step 1: Update interface signatures**
Add `ctx context.Context` as the first parameter to all methods in `EscalationTokenStore` and `PendingEscalationStore`.

- [x] **Step 2: Update File and Memory implementations**
Update `TokenStore` and `InMemoryPendingStore` to accept the context parameter (even if ignored initially).

- [x] **Step 3: Update EscalationManager calls**
Thread the request context through all store calls in `EscalationManager`.

---

### Task 7: Key Partitioning Logic

**Files:**
- Modify: `internal/gate/tokenstore.go`
- Modify: `internal/gate/escalation_manager.go`

- [x] **Step 1: Implement resolveStoragePrefix helper**
In `tokenstore.go`, implement `resolveStoragePrefix(ctx context.Context, scope string, identity IdentitySource) string` following the design (Session ID for "session", Fingerprint/UserID for "fingerprint").

- [x] **Step 2: Implement key collision prevention**
In `EscalationManager.StorePending`, change the key format from `server/tool` to `resolveStoragePrefix(ctx, ...) + ":" + serverName + "/" + toolName`.

---

### Task 8: Redis Store Implementations

**Files:**
- Create: `internal/gate/redis_pending_store.go`
- Create: `internal/gate/redis_token_store.go`
- Modify: `internal/gate/server.go`

- [x] **Step 1: Implement RedisPendingStore**
Fulfill `PendingEscalationStore` using Redis `GET`, `SET EX`, and `DEL`. Use the `resolveStoragePrefix` for key namespacing.

- [x] **Step 2: Implement RedisTokenStore**
Fulfill `EscalationTokenStore` using Redis `SADD`, `SMEMBERS`, and `SREM`.

- [x] **Step 3: Wire stores in Gate.New**
If `cfg.Operations.Storage.Backend == "redis"`, instantiate the Redis stores.

---

### Task 9: Proactive Flow Standardization

**Files:**
- Modify: `internal/gate/server.go`
- Modify: `internal/gate/escalation_manager.go`

- [x] **Step 1: Remove isProactive conditional logic**
Delete `isProactive()` and update all callers to assume true.

- [x] **Step 2: Update buildEscalationMessage**
Ensure it always uses the short `?jti=` URL format.

- [x] **Step 3: Update StorePending error handling**
If `RegisterPending` on Guard fails, return a specific error that the error mapper can convert into "Authorization system unavailable" for the Agent.

---

### Task 10: Telemetry & Status Propagation

**Files:**
- Modify: `internal/gate/guardclient.go`
- Modify: `internal/gate/escalation_manager.go`

- [x] **Step 1: Surface HTTP Status in GuardClient**
Create `GuardAPIError{StatusCode int, Err error}`. Update `ClaimToken` to return this error when appropriate.

- [x] **Step 2: Implement lazy_claim logging**
In `EscalationManager.CollectTokens`, implement the structured log entry with all fields (`phase`, `jti`, `elapsed_ms`, etc.).

- [x] **Step 3: Add hashing documentation**
Add a code comment in `CollectTokens` documenting the hashing algorithm for `scope_key_hash`.

---

### Task 11: Verification & Integration Tests

**Files:**
- Create: `internal/gate/multi_tenant_escalation_test.go`

- [x] **Step 1: Add proactive dependency test**
Test that Guard connection failure results in the correct "Authorization system unavailable" message.

- [x] **Step 2: Add multi-tenant escalation integration test**
Simulate a full flow in multi-tenant mode: tool call -> escalate URL -> manual deposit to Guard -> retry -> success.
