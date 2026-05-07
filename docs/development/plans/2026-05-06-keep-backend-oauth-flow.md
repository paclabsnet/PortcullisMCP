# Plan: Unified Backend Identity & Authentication (CredentialsStore)

**Date:** 2026-05-07
**Status:** Approved (Architecture)

**Hard constraints:**
- Keep is always multi-user.
- Keep operates as a cluster. All shared state must be stored in a pluggable `CredentialsStore` (Redis by default).
- The agent only manages its Portcullis token; Keep manages all backend credentials.

**Context:** This plan unifies how Keep injects identities and credentials into backend MCP
requests. It replaces the separate identity-exchange and proposed oauth blocks with a
single `user_identity` strategy that supports multiple types: `none`, `exchange`,
`api_key`, and `oauth`.

---

## Architectural Principle: Unified Identity Strategy

Keep uses a single `user_identity` configuration per backend to determine what
credential to inject and where to place it (HTTP Header or JSON Path).

- **Separated Domains:** The agent never sees backend credentials. Keep handles all
  discovery, storage, and injection.
- **Pluggable Storage:** Secrets (tokens) are stored in a `CredentialsStore` to
  support cluster-wide availability and future Vault integration.

---

## Configuration Model: `user_identity`

The `mcp_backends[].user_identity` block is expanded with a `type` discriminator.

```yaml
mcp_backends:
  - name: "enforceauth"
    user_identity:
      type: "oauth" # Options: none, exchange, api_key, oauth
      
      # Shared placement logic (works for all types)
      placement:
        header: "Authorization" # Default for oauth/exchange
        # json_path: "context.user" # Alternative
      
      # Type-specific configurations
      oauth:
        client_id: "portcullis-keep"
        callback_url: "https://portcullis.corp.com/keep/oauth/callback"
        scopes: ["mcp:read"]
        refresh_window: 60s # Optional; default 30s. Attempt refresh before expiry.
        flow_timeout: 20m    # Optional; default 10m. TTL for the pending flow state.
        store_refresh_tokens: true # Optional; default true. If false, refresh tokens are discarded.

      api_key:
        source: "envvar://MCP_KEY" # Uses existing secrets resolver

      exchange:
        url: "https://exchange.internal/token"
        # ... existing exchange fields (cache, timeout, etc.) ...
```

### Strategy Behaviors & Failure Semantics
1.  **`none` (Default):** Success by definition. No credential is ever injected.
2.  **`exchange`:** Calls an external webhook. If exchange fails, Keep **omits** the credential and proceeds (fail-open/silent-degrade). This preserves existing behavior for optional identity enrichment.
3.  **`api_key`:** Injects a static secret. Keep **fails-closed at startup** if the `source` URI cannot be resolved.
4.  **`oauth`:** Performs the managed flow. Keep **fails-to-auth**: if no token is found or the token is rejected by the backend, Keep initiates the OAuth flow and returns an "Authentication Required" result to the agent. It **never** silently degrades to an unauthenticated backend call.

---

## Storage Abstraction: `CredentialsStore`

Secrets are managed through a pluggable interface in `internal/keep/credentials_store.go`.

```go
type CredentialsStore interface {
    // User Tokens (OAuth Access/Refresh tokens, etc.)
    GetToken(ctx context.Context, backend, userID string) (*userToken, error)
    SetToken(ctx context.Context, backend, userID string, token *userToken) error
    DeleteToken(ctx context.Context, backend, userID string) error

    // PKCE State (Short-lived, cluster-wide nonce/verifier)
    StorePending(ctx context.Context, nonce string, p *pendingAuth) error
    ConsumePending(ctx context.Context, nonce string) (*pendingAuth, error)

    // Client Registrations (Metadata for Dynamic Client Registration)
    GetClientReg(ctx context.Context, backend string) (*clientReg, error)
    SetClientReg(ctx context.Context, backend string, reg *clientReg) error
}
```

---

## Scope of Work

### 1. Unified Configuration & Validation
- Update `internal/keep/config.go` to support the new `user_identity` fields and `type` discriminator.
- **Fail-Fast Validation (at startup):** 
  - The type-specific block (`oauth:`, `api_key:`, or `exchange:`) **must** be present when `type` is not `none`.
  - `oauth` requires `callback_url`.
  - `callback_url` must be a valid URL. In production mode, it **must** use HTTPS. dev mode can be http and can be localhost/127.0.0.1
  - `refresh_window` and `flow_timeout` must be valid Go duration strings (e.g. `30s`, `10m`).
  - `api_key` requires `source`.
  - `exchange` requires `url`.
  - `oauth` requires a `CredentialsStore` to be configured in `operations`.
- **Operational Warnings:**
  - Emit a strong startup warning (INFO/WARN) if `oauth` is enabled but the `CredentialsStore` strategy is `memory`:
    "backend OAuth state is process-local; restarts and failover will lose pending auth flows and tokens."

### 2. CredentialsStore Implementation
- Implement `memoryCredentialsStore` (default/dev) and `redisCredentialsStore` (production).
- Redis implementation uses `portcullis:keep:oauth:` prefixes and `GETDEL` (Redis 6.2+).
- We'll add a vault-based store in the future

### 3. OAuth Flow Implementation
- **Callback Handler:** `GET /oauth/callback` performs the code exchange and stores the token.
  - **On Failure (Expired/Missing):** Return a user-friendly error page: "Authentication flow expired or already completed. Please return to your AI assistant and retry the tool call."
- **Flow Initiation:** When a backend returns 401, Keep returns a `CallToolResult` with the authorization URL.
- **Injection:** `headerInjectingRoundTripper` fetches tokens from the `CredentialsStore` based on the configured `type`.

### 4. Background Token Refresh
- If an OAuth token is near expiry, Keep attempts an optimistic refresh before the next tool call.

---

## Security Considerations
- **Proxy-First:** Constructing redirect URIs using an explicit `callback_url` ensures compatibility with reverse proxies.
- **Isolation:** Backend credentials never leave the Keep/Store boundary.
- **Nonce Integrity:** Atomic `GETDEL` ensures single-use nonces for the OAuth flow.
