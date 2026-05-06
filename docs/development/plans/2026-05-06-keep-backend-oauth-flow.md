# Plan: OAuth 2.1 Client Flow for Keep Backend Authentication

**Date:** 2026-05-06
**Status:** Under review

**Hard constraints:**
- Keep is always multi-user.
- Keep operates as a cluster. All shared state must be stored in Redis.
  In-memory state (per-process maps, etc.) is not acceptable for anything that
  must survive failover or be visible across instances.

**Context:** When Keep proxies to an MCP backend that requires OAuth (e.g. EnforceAuth),
the current behavior is to return an auth error to the agent. This plan describes what
would be required to make Keep handle the OAuth flow itself, so the user experience
matches what happens when an agent connects directly to such a backend.

---

## Background

When Claude connects to an MCP-over-HTTP backend directly, it performs the MCP OAuth 2.1
flow automatically:
1. Backend returns 401 with `WWW-Authenticate: Bearer resource_metadata=<url>`
2. Claude fetches Protected Resource Metadata (RFC 9728) from that URL
3. Claude fetches Authorization Server Metadata (RFC 8414)
4. Claude initiates Authorization Code + PKCE (RFC 7636)
5. User logs in via browser
6. Claude exchanges the code for a token and uses it

When Portcullis is in the middle, Keep is the MCP client. Claude only talks to Gate.
Gate has no knowledge of backend auth requirements. Keep must perform the OAuth flow
on behalf of each user, coordinating state across a cluster via Redis.

---

## Architectural Principle: Separated Auth Domains

This design rests on a clean separation that holds for both single-tenant (stdio) and
multi-tenant (HTTP) Gate deployments:

- **The agent manages one credential: its Portcullis token.** In single-tenant mode
  this is established via Gate's identity strategy (oidc-login, oidc-file, etc.) over
  stdio. In multi-tenant mode it is a Bearer token obtained via the standard MCP
  OAuth 2.1 flow against Gate's own auth server (e.g. Dex), included in the HTTP
  `Authorization` header.

- **Keep manages all backend credentials.** Backend OAuth tokens are stored in Redis
  keyed by `(backend, userID)`, injected into outgoing backend requests by
  `headerInjectingRoundTripper`, and never surfaced to the agent.

This means there is no auth header collision between the agent's Portcullis credential
and backend credentials, in either transport mode:

- *Single-tenant (stdio):* There is no HTTP `Authorization` header between agent and
  Gate at all. Backend tokens are invisible to the agent.
- *Multi-tenant (HTTP):* Gate consumes and validates `Authorization: Bearer
  <portcullis-token>`. That header never reaches Keep or the backends. Backend tokens
  travel only on Keep→backend connections, managed entirely within Keep.

The agent only ever knows about one auth domain. Keep is solely responsible for the
other.

---

## What Is Already in Place

- Redis is already in the stack; Keep has a `StorageConfig` that supports it
- `golang.org/x/oauth2` is already a dependency (PKCE, token exchange)
- go-sdk `oauthex` package provides:
  - `GetProtectedResourceMetadataFromHeader` — parses `WWW-Authenticate` and fetches PRM
  - `GetAuthServerMeta` — fetches Authorization Server Metadata (RFC 8414)
  - Full RFC 9110-compliant WWW-Authenticate header parser
- `backendRespCapture` in `router.go` already captures the 401 status and response headers
- `headerInjectingRoundTripper` already knows how to inject headers into backend requests
- Keep's HTTP mux is readily extensible with new routes
- Gate's `enrichBackendAuthChallenge` already formats auth errors for the agent
- Keep already extracts and carries user identity through its request context

---

## Redis Key Schema

All keys are prefixed with `portcullis:keep:oauth:` to avoid collisions with other
Keep data in a shared Redis instance.

| Key | TTL | Value | Purpose |
|-----|-----|-------|---------|
| `portcullis:keep:oauth:token:{backend}:{userID}` | = token expiry | JSON `userToken` | Per-user access + refresh token |
| `portcullis:keep:oauth:state:{nonce}` | 10 min | JSON `pendingAuth` | PKCE flow in progress |
| `portcullis:keep:oauth:client:{backend}` | none (permanent) | JSON `clientReg` | Dynamic client registration result |

The `{userID}` component must be normalized (e.g. URL-encoded or hashed) if it can
contain characters that are special in Redis key paths.

---

## Scope of Work

### 1. Redis-Backed OAuth Token Store

A new `oauthTokenStore` type backed by Redis.

```
type userToken struct {
    AccessToken   string    `json:"access_token"`
    RefreshToken  string    `json:"refresh_token,omitempty"`
    Expiry        time.Time `json:"expiry"`
    TokenEndpoint string    `json:"token_endpoint"`
}
```

Operations:
- `Get(ctx, backend, userID) (*userToken, error)` — GET + JSON unmarshal
- `Set(ctx, backend, userID, token *userToken) error` — SET with EXAT (absolute expiry)
- `Clear(ctx, backend, userID) error` — DEL

The Redis key TTL is set to the token's `Expiry` (access token lifetime). When the
key expires in Redis, the next call re-triggers the OAuth flow. Refresh tokens, if
present, must be considered: the token should be refreshed before the access token
expires, not after the Redis key disappears. The `Get` operation checks whether
`expiry - 30s < now` and signals the caller to refresh proactively.

### 2. Redis-Backed PKCE State Map

```
type pendingAuth struct {
    CodeVerifier  string `json:"code_verifier"`
    BackendName   string `json:"backend_name"`
    UserID        string `json:"user_id"`
    TokenEndpoint string `json:"token_endpoint"`
    ClientID      string `json:"client_id"`
    RedirectURI   string `json:"redirect_uri"`
}
```

Operations:
- `StorePending(ctx, nonce string, p *pendingAuth) error`
  SET `portcullis:keep:oauth:state:{nonce}` EX 600 (10 min)
- `ConsumePending(ctx, nonce string) (*pendingAuth, error)`
  Atomic GET-then-DEL using a Lua script or GETDEL (Redis 6.2+).
  Returns `nil, nil` if not found (expired or already consumed).
  Single-use: consuming deletes the key, preventing replay.

Using GETDEL ensures that even if two cluster nodes receive the same callback
simultaneously (unlikely but theoretically possible), only one succeeds.

### 3. Redis-Backed Client Registration Cache

Dynamic Client Registration (RFC 7591) produces a `client_id` and optionally a
`client_secret`. These are per-backend (not per-user) and should be shared across
cluster nodes.

```
type clientReg struct {
    ClientID     string `json:"client_id"`
    ClientSecret string `json:"client_secret,omitempty"`
}
```

Operations:
- `GetClientReg(ctx, backend string) (*clientReg, error)` — GET + unmarshal
- `SetClientReg(ctx, backend string, reg *clientReg) error` — SET (no TTL; permanent)

No TTL is set because client registrations are long-lived. If the registration
is ever revoked by the auth server, the next 401 will clear it and re-register.

### 4. OAuth Callback HTTP Handler (`internal/keep/server.go`)

A new route on Keep's existing mux, registered before the auth middleware
(browser redirects carry no Bearer token):

```
GET /oauth/callback?code=...&state=...
```

The backend name is NOT in the URL path — it is recovered from the Redis state
entry. This prevents backend names from appearing in browser history.

Responsibilities:
1. Extract `state` (nonce) from query params; reject if absent or malformed.
2. Call `ConsumePending(ctx, nonce)` — atomic GET+DEL from Redis.
   If nil (expired or already consumed), return 400 with a user-facing error page.
3. POST to `pendingAuth.TokenEndpoint`:
   - `grant_type=authorization_code`
   - `code=<code from query param>`
   - `code_verifier=<from pendingAuth>`
   - `redirect_uri=<from pendingAuth>`
   - `client_id=<from pendingAuth>`
   - `client_secret` if applicable
4. On success: call `Set(ctx, backend, userID, token)` to store the token in Redis.
5. Return a minimal HTML page: "Authentication complete. Close this tab and retry
   your request in the AI assistant."
6. On failure: return a clear error page; do not store a token.

Because `ConsumePending` is atomic, this handler is safe under concurrent requests
from multiple Keep nodes.

### 5. Flow Initiation in `router.go`

After `backendRespCapture` captures a 401 from a backend, check for OAuth discovery
before returning the generic error result:

```go
if statusCode == 401 {
    if result := r.tryStartOAuthFlow(ctx, serverName, headers); result != nil {
        return result, nil
    }
}
```

`tryStartOAuthFlow(ctx, serverName, headers)`:

1. Extract `userID` from the identity in `ctx`. If absent, return nil (fall through
   to generic error — cannot associate a flow with an unknown user).
2. Check `Get(ctx, serverName, userID)` in the token store. If a valid token exists,
   the backend rejected it unexpectedly: call `Clear`, return an error result
   ("Your token for 'enforceauth' was rejected. Re-authentication required.").
3. Call `oauthex.GetProtectedResourceMetadataFromHeader(ctx, headers, httpClient)`.
   If nil or error, return nil (not an OAuth-capable backend; use generic error).
4. Take the first authorization server from `prm.AuthorizationServers`.
5. Call `oauthex.GetAuthServerMeta(ctx, authServerURL, httpClient)`.
   On failure, return an error result to the agent.
6. Determine `client_id`:
   - If `BackendConfig.OAuth.ClientID` is set, use it directly.
   - Otherwise call `GetClientReg(ctx, serverName)`. If found in Redis, use it.
   - Otherwise POST to `asm.RegistrationEndpoint` (RFC 7591). On success, call
     `SetClientReg(ctx, serverName, reg)`. On failure (no endpoint, or rejected),
     return an error result explaining that a `client_id` must be configured.
7. Generate PKCE: `code_verifier` = 64 random bytes base64url-encoded;
   `code_challenge` = base64url(SHA-256(code_verifier)).
8. Generate nonce = 32 random bytes base64url-encoded.
9. Call `StorePending(ctx, nonce, &pendingAuth{...})` — stored in Redis with 10 min TTL.
10. Build authorization URL from `asm.AuthorizationEndpoint`:
    `response_type=code`, `client_id`, `redirect_uri`, `state=<nonce>`,
    `code_challenge`, `code_challenge_method=S256`, scopes from PRM or config.
11. Return:
    ```
    CallToolResult{IsError: true, Content: [{type: text, text:
      "Authentication required for backend 'enforceauth'.
       Open this URL in your browser to log in, then retry this tool call:

         https://auth.enforceauth.dev/authorize?...

       This link expires in 10 minutes."
    }]}
    ```

### 6. Per-User Token Injection in `headerInjectingRoundTripper`

At the top of `RoundTrip`, before any header copying:

1. Extract `userID` from context (existing identity context value).
   If no identity, skip — the backend will 401 and trigger the flow.
2. Call `Get(ctx, backendName, userID)` on the token store.
3. If a valid token is found:
   - If `expiry - 30s > now`: inject `Authorization: Bearer <accessToken>`.
   - If near expiry and `refreshToken` is present: attempt token refresh (POST to
     `tokenEndpoint` with `grant_type=refresh_token`). On success, update Redis and
     inject the new access token. On failure, call `Clear` and proceed without
     injection (the next 401 re-triggers the flow).
4. If no token found, proceed without injection.

Token refresh is done optimistically (before the token actually expires) to avoid
a user-visible 401 on expiry. If two cluster nodes attempt a refresh simultaneously
for the same user+backend, both will succeed and the later write wins — this is
acceptable since both will yield valid tokens.

### 7. Per-Backend OAuth Config (`internal/keep/config.go`)

A new optional `oauth` block in `BackendConfig`:

```yaml
mcp_backends:
  - name: "enforceauth"
    type: "http"
    url: "https://mcp.enforceauth.dev/t/..."
    oauth:
      client_id: "portcullis-keep"           # omit to use dynamic registration
      client_secret: "${ENFORCEAUTH_SECRET}"  # omit if public client (PKCE only)
      scopes: ["mcp:read", "mcp:write"]       # optional; overrides PRM scopes
```

Validation:
- `oauth` block is entirely optional. If absent, OAuth flows are not initiated
  for this backend (existing behavior preserved).
- If `oauth` is present but `client_id` is absent and the auth server has no
  registration endpoint, Keep returns a config validation error at startup.

### 8. Config: Callback Base URL

New optional field in `ServerConfig`:

```yaml
server:
  oauth_callback_base_url: "http://localhost:8080"
```

Keep constructs: `<oauth_callback_base_url>/oauth/callback`

If `oauth_callback_base_url` is absent but any backend has an `oauth` block,
Keep returns a config validation error at startup (the redirect URI is required
for all Authorization Code flows).

---

## Observability: Per-User Token Storage Logging

Because per-user OAuth token storage is a consequence of the backend's auth requirements
(not a choice Portcullis makes independently), Keep should make this visible to admins
through its logs so they understand what credentials are being held and why.

Specifically:

- At startup, for each backend with an `oauth` block configured, log at INFO level:
  `backend "enforceauth" is configured for per-user OAuth token storage (required by backend)`
- When a new token is stored for a user: log at DEBUG level with backend name and
  userID (no token value).
- When a token is refreshed: log at DEBUG level with backend name and userID.
- When a token is cleared (expired, rejected, or revoked): log at INFO level with
  backend name, userID, and reason.
- When the OAuth flow is initiated for a user: log at INFO level with backend name
  and userID.

Token values, code verifiers, and client secrets must never appear in logs at any level.

---

## What Is Not Covered Here

- **Token revocation** when a user's Portcullis session ends or a backend is removed.
  Tokens will expire naturally via Redis TTL.
- **mTLS-bound tokens / DPoP** (RFC 9449)
- **Client credentials grant** (service-to-service, no user interaction). This is a
  simpler separate feature: no callback, no PKCE, no per-user state; just a
  shared token stored in Redis under `portcullis:keep:oauth:token:{backend}:__service__`.
- **Static API key credentials via `X-Portcullis-Auth`:** For backends that issue
  long-lived API keys rather than short-lived OAuth tokens, a simpler pattern is
  available. The user configures their MCP client to include a custom
  `X-Portcullis-Auth: Bearer <key>` header in all requests to Gate. Gate's
  `ForwardHeaders` config passes this through to Keep, and Keep's
  `headerInjectingRoundTripper` forwards it to the backend. This avoids the full OAuth
  flow entirely and requires no Keep-side state. It does not conflict with the
  `Authorization` header used for the Portcullis credential. This is analogous to how
  Portkey uses a custom `x-portkey-api-key` header for its own identity. This pattern
  is worth documenting separately as it covers many real-world cases without the
  complexity of the full OAuth flow described in this plan.

---

## Security Considerations

- The `state` nonce is 256 bits of randomness; unguessable. The user ID and
  code_verifier are stored in Redis only, never in the browser.
- `ConsumePending` is atomic (GETDEL); a nonce can only be used once even across
  cluster nodes.
- The callback endpoint has no Bearer auth, but its security relies entirely on
  nonce unguessability (standard OAuth PKCE model, per RFC 7636 §1).
- Access tokens and refresh tokens are stored in Redis. Redis must be treated as
  a secrets store: use AUTH, TLS, and restrict network access accordingly.
  The existing Redis config in Keep should already satisfy this.
- Dynamic client registration secrets must not be logged above DEBUG level.
- The `oauth_callback_base_url` must use HTTPS in production. OAuth authorization
  servers may reject HTTP redirect URIs for non-localhost URLs.

---

## Open Questions

1. **Static `client_id` vs. dynamic registration:** Does EnforceAuth require dynamic
   registration, or can a `client_id` be pre-registered and configured statically?
   Static config is simpler and should be attempted first.

2. **Callback reachability:** Is Keep's HTTP port reachable from users' browsers in all
   deployment scenarios? Behind a reverse proxy or in a cloud deployment, the
   `oauth_callback_base_url` must point to the public URL of the proxy. This is an
   operational concern but must be documented clearly.

3. **Redis version requirement:** Redis 6.2+ is required (for `GETDEL`). This is a
   documented system requirement for Keep.

4. **Token lifetime vs. scope:** EnforceAuth tokens may be scoped per-resource or
   per-user. If Keep calls multiple tools on the same backend in one session, a single
   token per (backend, user) should suffice. If scopes differ per tool, this needs
   revisiting.
