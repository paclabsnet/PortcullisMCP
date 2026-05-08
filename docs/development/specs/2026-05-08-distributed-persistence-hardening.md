# Design Spec: Distributed Persistence Hardening

**Date:** 2026-05-08
**Status:** Draft
**Topic:** Ensuring system-wide robustness and "outage-free" failover in multi-tenant distributed deployments.

## 1. Objective
Portcullis services (Gate, Guard, Keep) must be "horizontally scalable" in multi-tenant mode. Currently, several critical authentication and escalation states are stored in process-local memory or local files, which causes functional outages (e.g., "invalid login session", "token not found") if a user's request hits a different instance during a flow.

This spec defines the transition of all "outage-critical" state to a standardized distributed storage layer (Redis) when multi-tenancy is enabled.

## 2. Architecture Overview
We will move away from hardcoded in-memory maps and local files for transient state. Every component that manages state during an interactive flow will use an interface-based store that defaults to `Memory` (for single-instance/stdio use) but can be wired to `Redis` (for distributed use).

### Storage Tier Mapping
| State Type | Component | Current Storage | Distributed Storage (Option A) |
| :--- | :--- | :--- | :--- |
| **OIDC Login PKCE** | Gate | `map` (local) | Redis (via `GETDEL`) |
| **Escalations (Pending & Approved)** | Gate | `InMemoryStore` / `tokens.json` | **Unified EscalationStore (Redis-backed)** |
| **Guard UI Login/PKCE** | Guard | `MemStore` | Redis (via `GETDEL`) |
| **Guard UI Sessions** | Guard | `MemStore` | Redis |

## 3. Component Details

### 3.1 Gate: Distributed OIDC Login
The `OIDCLoginManager` in `internal/gate/oidclogin.go` currently stores `pkceSession` in a local map.
- **New Interface:** `OIDCSessionStore` with `Store(state, session)`, `Get(state)`, and `Delete(state)`.
- **Redis Implementation:** Uses `portcullis:gate:oidc:pkce:{state}` as the key. `Get` will use `GETDEL` to ensure the PKCE state is single-use and cleared immediately upon consumption.

### 3.2 Gate: Unified EscalationStore
To simplify distributed coordination, we will consolidate the management of both **Pending Escalations** and **Approved Tokens** into a single `EscalationStore` interface.

- **The Interface:**
    ```go
    type EscalationStore interface {
        // Pending Ops
        StorePending(ctx context.Context, key string, p pendingEscalation) error
        GetPending(ctx context.Context, key string) (pendingEscalation, bool, error)
        DeletePending(ctx context.Context, key string) error
        
        // Approved Token Ops
        AllTokens(ctx context.Context) ([]shared.EscalationToken, error)
        AddToken(ctx context.Context, tok shared.EscalationToken) error
        DeleteToken(ctx context.Context, tokenID string) error
    }
    ```

- **Single-Tenant Implementation:**
    - Uses an in-memory map for Pending escalations.
    - Uses the existing `tokens.json` file-backing for Approved tokens (to persist across restarts).

- **Multi-Tenant Implementation (Redis):**
    - **Pending:** Stored as standard Redis keys with TTL: `portcullis:gate:escalation:pending:{key}`.
    - **Approved:** Stored in a Redis Hash keyed to the session: `portcullis:gate:escalation:tokens:{sessionID}`. 
    - This ensures that when any Gate instance in a cluster claims a token, it is immediately available to all other instances serving that same user session.

### 3.3 Guard: Distributed Management UI
Guard's `Server` in `internal/guard/server.go` manages OIDC login for administrators approving requests.
- **AuthStore Implementation:** The existing `AuthStore` interface will be extended with a Redis-backed implementation.
- **Redis Implementation:**
    - PKCE state: `portcullis:guard:auth:pkce:{state}` (with `GETDEL`).
    - Sessions: `portcullis:guard:auth:session:{sid}`.

## 4. Implementation Strategy

### 4.1 Phase 1: Shared Redis Utilities
Ensure all components can share a Redis connection pool and key-prefixing logic. Update `internal/shared/config` to provide a common `RedisConfig` consumer.

### 4.2 Phase 2: Guard Hardening
1. Implement `RedisAuthStore` satisfying the existing `AuthStore` interface.
2. Update `NewServer` in `internal/guard/server.go` to initialize `RedisAuthStore` when Redis storage is configured.
3. Ensure OIDC session cookies (`SetSessionCookie`) work correctly with the distributed store.

### 4.3 Phase 3: Gate Hardening
1.  Implement `RedisEscalationStore` satisfying the `EscalationStore` interface.
    -   Pending state uses standard Redis keys.
    -   Approved tokens use a Redis Hash (`portcullis:gate:escalation:tokens:{sessionID}`).
2.  Refactor `EscalationManager` to consume the unified `EscalationStore` instead of separate `PendingEscalationStore` and `EscalationTokenStore` interfaces.
3.  Update the `Gate` constructor to inject the correct `EscalationStore` (Memory/File for single-tenant, Redis for multi-tenant).
4.  Refactor `OIDCLoginManager` to use `OIDCSessionStore` and implement `RedisOIDCSessionStore`.

## 5. Success Criteria
1. **No "Invalid Login" on Failover:** A user can start OIDC login on Gate A and finish on Gate B.
2. **Global Polling:** Gate B can successfully poll and claim a token for an escalation that was triggered by Gate A.
3. **Exactly-Once Token Claim:** In a multi-Gate environment, only one Gate instance can successfully claim a specific escalation token from Guard. Concurrent claim attempts for the same JTI must resolve atomically, with exactly one winner.
4. **No Session Loss:** Restarting any individual Gate or Guard instance does not log out users or administrators.
5. **Backward Compatibility:** Single-tenant `stdio` mode continues to work with zero external dependencies (no Redis required).

## 6. Security Considerations
- **Atomic Consumption:** `GETDEL` is mandatory for PKCE and Nonce state to prevent replay attacks in a distributed race.
- **Encryption:** Session data in Redis should ideally be encrypted (using `operations.interface.session_secret` if available).
- **TTL:** All distributed transient state MUST have a Redis TTL consistent with the configured session/flow timeouts.
