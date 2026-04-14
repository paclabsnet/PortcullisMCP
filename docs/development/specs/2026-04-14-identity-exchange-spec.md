# Design Spec: Identity Exchange for MCP Backends

**Date:** 2026-04-14
**Status:** Draft
**Owner:** Gemini CLI

## 1. Problem Statement
Portcullis-Keep currently forwards the user's raw OIDC JWT to backend MCP servers. Enterprise MCPs often require identity formats that differ from the standard JWT (e.g., a simple user ID, a custom JSON structure, or an XML payload). We need a mechanism to transform the standard JWT into a backend-specific identity before it reaches the MCP.

## 2. Goals
- Provide a configurable "Identity Exchange" service per MCP backend.
- Minimize latency through a robust caching layer (Memory/Redis).
- Ensure security through SSRF protection for exchange URLs.
- Maintain backward compatibility for backends not requiring exchange.

## 3. User Experience (Configuration)
In `keep.yaml`, users can now configure exchange parameters per backend:

```yaml
responsibility:
  mcp_backends:
    - name: "enterprise-service"
      type: "http"
      url: "http://internal-mcp:8080/mcp"
      user_identity:
        placement:
          header: "X-Enterprise-ID"
          json_path:
        exchange:
          url:  "https://identity-service.corp/exchange"
          timeout:
          cache:
            ttl: 600 # 10 minutes
            max_entries:
          auth_headers:
            Authorization: "Bearer envvar://EXCHANGE_API_TOKEN"  
            X-Client-ID: "portcullis-keep-01"
```

## 4. Technical Design

### 4.1. Identity Exchange Client
A new `IdentityExchangeClient` will be implemented in `internal/keep/identity_exchange.go`.
- **Method:** `POST`
- **Request Body:** `{"token": "<original_jwt>"}`
- **Headers:** Includes any custom headers defined in `user_identity.exchange.auth_headers`.
- **Response Contract:**
  - **Required Content-Type:** `application/json`
  - **Required Schema:** `{ "identity": "<string_or_object>" }`
  - **Encoding:** UTF-8
  - **Max Response Size:** 16 KB. Responses exceeding this size MUST be rejected.
  - **Processing:** The value of the `identity` field is extracted. If it is a string, it is used as-is (trimmed). If it is a JSON object/array, it is serialized to JSON before being used for injection (header or path).
  - **Rejection Criteria:** Keep MUST return `502 Bad Gateway` if:
    - The `Content-Type` is not `application/json`.
    - The response is not valid JSON.
    - The `identity` field is missing or null.
    - The response exceeds 16 KB.

### 4.2. Caching Layer
A new `TokenCacher` interface will be added to `internal/keep/token_cache.go`, mirroring the existing `PrincipalCacher`.
- **Implementations:** 
  - `TokenCache`: LRU in-memory cache with TTL.
  - `RedisTokenCache`: Redis-backed cache for clustered deployments.
- **Cache Key:** `backend_name` + `sha256(rawToken)` to ensure user-level and backend-level isolation.
- **Effective TTL Logic:** To prevent identity reuse after source token expiry, the cache TTL MUST be calculated as follows:
  - If the source token is a JWT with an `exp` claim: `Effective TTL = min(IdentityExchangeCacheTTL, (exp - now))`.
  - If no `exp` claim is present or the token is not a JWT: `Effective TTL = IdentityExchangeCacheTTL`.
  - If `Effective TTL <= 0`, the token MUST NOT be cached.

### 4.3. Router Integration
The `Router` in `internal/keep/router.go` will be the orchestration point.
1. `CallTool` extracts the `rawToken` from the context.
2. If `user_identity.exchange.url` is present:
   - Check cache.
   - If miss, call `IdentityExchangeClient`.
   - Update cache.
   - **Update Context:** Use `withRawToken(ctx, exchangedToken)` to replace the token in the request context.
3. Downstream logic for `IdentityPath` and `IdentityHeader` (in the `RoundTripper`) will automatically use the exchanged token from the updated context.

## 5. Failure Handling (Normative Policy)
To prevent accidental leakage of the original JWT and ensure predictable system behavior, the following policy matrix defines the required response for various failure modes.

### 5.1. Policy Matrix
| Failure Mode | Behavior | Required Action | Original Token Fallback? |
| :--- | :--- | :--- | :--- |
| **Exchange Timeout** | **Fail-Degraded** | Log error (redacted); proceed **without** injection | **No** |
| **Exchange Non-2xx** | **Fail-Degraded** | Log error (redacted); proceed **without** injection | **No** |
| **Malformed Response Body** | **Fail-Degraded** | Log error (redacted); proceed **without** injection | **No** |
| **Cache Read Error** | Fail-Open (to Exchange) | Log error; proceed to call Identity Exchange service | N/A |
| **Cache Write Error** | Fail-Open (to Request) | Log error; proceed with the tool call (do not fail the request) | N/A |
| **SSRF / Invalid URL** | **Fail-Degraded** | Log error, hard fail | **No** |

### 5.2. Redaction & Logging
All logs related to identity exchange failures **MUST NOT** include the raw content of the original JWT or the (potentially partial) exchanged token. Logs should reference the `trace_id` and the `backend_name` only.

## 6. Security Considerations
- **No Original Token Fallback:** If `user_identity.exchange.url` is configured, the system MUST NOT forward the original JWT under any error condition.
- **Fail-Degraded Logic (Omission):** When an exchange fails or returns an empty value, the `user_identity.placement.header` MUST be omitted entirely from the outgoing request, and the `user_identity.placement.json_path` MUST NOT be added to the request arguments.
- **SSRF Protection (Parity with Backends):** The `user_identity.exchange.url` MUST adhere to the following security constraints:
  - **Redirect Blocking:** The HTTP client MUST NOT follow redirects. Any redirect attempt MUST result in a `502 Bad Gateway`.
  - **Scheme Restriction:** Only `http` and `https` schemes are permitted.
  - **Host Resolution Policy:** Unless `allow_private_addresses: true` is set for the backend, the exchange URL MUST NOT resolve to RFC 1918, loopback, or link-local addresses. Validation MUST occur at both configuration load time (DNS lookup) and request time (via no-redirect policy).
- **Token Leakage:** The exchange is performed server-side (Keep to Identity Service), never exposing the original JWT to the backend MCP if an exchange is used.
- **Context Isolation:** The exchanged token is stored in the per-request context, preventing leakage between parallel requests from different users.

## 6. Implementation Plan Highlights
- Task 1: Extend `BackendConfig` and validation.
- Task 2: Implement `TokenCacher` (Memory and Redis).
- Task 3: Implement `IdentityExchangeClient` with HTTP POST.
- Task 4: Integrate into `Router.CallTool` and `Server` initialization.

## 7. Success Criteria
- [ ] Backend receives the exchanged token in the configured header.
- [ ] Backend receives the exchanged token at the configured JSON path.
- [ ] Cache successfully prevents redundant exchange calls.
- [ ] Existing non-exchanging backends are unaffected.


