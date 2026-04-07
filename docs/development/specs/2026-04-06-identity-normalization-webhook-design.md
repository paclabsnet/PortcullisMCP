# Identity Normalization Webhook Design

> **Feature:** Enable pluggable identity normalization via an optional enterprise webhook to map non-standard JWT claims to the Portcullis `Principal` structure, with built-in caching to minimize latency.

---

## Goal

Provide a robust extension point for enterprises with non-standard JWT claim structures. Instead of hard-coding every possible claim mapping into Portcullis, Keep will allow delegating the *interpretation* of trusted claims to an external service. A caching layer ensures that repetitive webhook calls do not introduce significant latency.

---

## Architecture

### 1. Separation of Concerns
Identity normalization is split into two distinct phases:
1.  **Cryptographic Validation**: Keep handles signature verification, issuer/audience checks, and expiry. This ensures the claims are authentic and trusted.
2.  **Mapping (Normalization)**: Claims are converted into the `shared.Principal` struct. This can be handled by:
    *   **Default Logic**: Best-effort mapping of standard claims (email, name, groups, roles).
    *   **External Webhook**: A POST call to an enterprise-provided service.

### 2. The Webhook & Cache Flow
When `peers.normalization.endpoint` is configured:
1.  Keep receives an `EnrichedMCPRequest`.
2.  Keep validates the OIDC or HMAC token cryptographically.
3.  **Cache Lookup**: Keep generates a cache key (SHA-256 hash of the `RawToken`). If a valid `Principal` exists in the cache, it is returned immediately.
4.  **Webhook Call**: If not cached, Keep POSTs the filtered map of claims to the configured `peers.normalization.endpoint`.
5.  Keep deserializes the response into a `shared.Principal`.
6.  **Cache Update**: The new `Principal` is stored in the cache with the configured TTL.

### 3. Data Minimization
To protect sensitive user data, Keep applies filters to the claims map BEFORE sending it to the webhook:
1.  **Allowlist**: If `peers.normalization.allow_claims` is configured, only the specified claims are included in the request body.
2.  **Denylist**: If `peers.normalization.deny_claims` is configured, the specified claims are explicitly removed from the request body.
3.  **Payload Size**: The total size of the request and response JSON bodies is limited by `peers.normalization.max_payload_kb` to prevent resource exhaustion and DoS attacks.

### 4. Response Validation
Keep validates the `shared.Principal` returned by the webhook against the configured limits:

1.  **UserID**: Must be present and its length must not exceed `max_userid_length`.
2.  **Groups**: If present, the number of groups must not exceed `max_groups_count`, and each group name's length must not exceed `max_group_name_length`.
3.  **Failure**: If any validation check fails, Keep denies the request with a `403 Forbidden` response to the caller, including a diagnostic error indicating the normalization failure.

---

## Configuration

The normalization webhook is configured as a **Peer** in the `peers` section, allowing it to leverage standard Portcullis authentication and transport settings. The cache and validation limits remain in the `identity` configuration.

### 1. Peer Configuration (`peers.normalization`)
```yaml
peers:
  normalization:
    # URL of the enterprise normalization service (MUST be https in production)
    endpoint: "https://identity-mapper.internal/map"

    # Standard Portcullis peer authentication
    auth:
      type: "bearer"
      credentials:
        # Field will be added to SecretAllowlist; supports vault:// and envvar://
        bearer_token: "vault://secret/portcullis/normalization-token"

    # Data minimization: claims sent to the webhook
    allow_claims: ["sub", "iss", "email", "groups", "x-corp-legacy-groups"]
    deny_claims: ["ssn", "private_key"]

    # Operational limits
    timeout: 10          # seconds
    max_payload_kb: 128  # max request/response body size
```

### 2. Identity Strategy Configuration (`identity.config`)
```yaml
identity:
  strategy: "oidc-verify" # or "hmac-verify"
  config:
    issuer: "https://idp.corp.com"
    jwks_url: "https://idp.corp.com/keys"
    
    # Cache settings for normalized principals
    cache_ttl: 600
    cache_max_entries: 5000

    # Validation limits for the Principal returned by the webhook
    # If exceeded, the request is denied with a 403 (Forbidden).
    max_userid_length: 256
    max_group_name_length: 128
    max_groups_count: 100
```

---

## API Contract

### Request (Keep -> Webhook)
**Method**: `POST`
**Content-Type**: `application/json`
**Body**: A JSON object containing the subset of claims extracted from the verified JWT, after applying the allowlist/denylist filters.

```json
{
  "sub": "alice-123",
  "iss": "https://idp.corp.com",
  "x-corp-legacy-groups": ["admins", "developers"]
}
```

### Response (Webhook -> Keep)
**Status**: `200 OK`
**Body**: A JSON object mapping to `shared.Principal`.

```json
{
  "user_id": "alice-123",
  "email": "alice@corp.com",
  "groups": ["admins", "developers"],
  "department": "Finance"
}
```

---

## Security Considerations

1.  **Cryptographic Trust**: The webhook is ONLY called after Keep has verified the JWT signature. The claims are already trusted.
2.  **Cache Integrity**: The cache key is derived from the verified token itself. If the token changes, the cache key changes.
3.  **Fail-Closed**: If the webhook returns an error or times out, Keep will fail the request with a 503 (Service Unavailable).
4.  **Transport Security**: To prevent credential leakage and MITM attacks, `peers.normalization.endpoint` MUST use `https://` when Keep is running in production mode (controlled by `mode: production`).
5.  **Credential Protection**: The `peers.normalization.auth.credentials.bearer_token` will be included in Keep's `SecretAllowlist`, allowing it to be securely injected via Vault or environment variables. It MUST NOT be stored in plain text in production configuration files.
6.  **Resource Limits**: In-memory cache size is managed via a combination of TTL-based expiry and a hard limit on the number of entries (`identity.config.cache_max_entries`). When the limit is reached, Least Recently Used (LRU) eviction ensures that frequently used entries are retained while preventing unbounded memory growth.
7.  **Data Minimization**: The use of `peers.normalization.allow_claims` and `peers.normalization.deny_claims` ensures that only the minimum necessary data is shared with the external webhook, reducing the risk of accidental exposure of PII or other sensitive claims.
8.  **DoS Protection**: Setting a maximum payload size (`peers.normalization.max_payload_kb`) prevents attackers from exhausting Keep's memory or CPU by sending or inducing extremely large JSON structures.
