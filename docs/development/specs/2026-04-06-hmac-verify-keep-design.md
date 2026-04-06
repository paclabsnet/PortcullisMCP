# Plan: Add `hmac-verify` Identity Normalizer to portcullis-keep

## Goal

Support HMAC-signed JWTs (HS256/HS384/HS512) as a user identity source in Keep, enabling integration with AWS AgentCore and other systems that issue HMAC tokens.

**Production Status**: `hmac-verify` is a fully production-supported alternative to `oidc-verify`. All production messaging, posture reports, and configuration validation logic must treat it with the same level of security and support as OIDC verification.

---

## Files Changed

### `internal/shared/identity/identity.go`

**Add `HMACVerifyConfig` struct:**

| Field | Type | YAML tag | Notes |
|-------|------|----------|-------|
| `Secret` | `string` | `secret` | Shared secret. Supports `envvar://` env var, or `vault://` secret substitution. |
| `Algorithm` | `string` | `algorithm` | `HS256`, `HS384`, or `HS512`. Defaults to `HS256` if empty. |
| `Issuer` | `string` | `issuer` | Optional. Token `iss` must match exactly if set. |
| `Audiences` | `[]string` | `audiences` | Optional. Token must contain at least one matching `aud` value. |
| `AllowMissingExpiry` | `bool` | `allow_missing_expiry` | If false (default), tokens without `exp` are rejected. Mirrors `oidc-verify` behaviour. |
| `MaxTokenAgeSecs` | `int` | `max_token_age_secs` | Optional. Maximum token age measured from `iat`. 0 means no enforcement. |

**Add `HMACVerify HMACVerifyConfig` field to `NormalizerConfig`:**
Tagged `yaml:"-"` — decoding is handled via mapstructure in `keep/config.go`, not direct YAML unmarshalling.

**Update `NormalizerConfig.Validate()` and `Build()`:**
- Accept `"hmac-verify"` as a valid normalizer name
- Require `Secret` to be non-empty when normalizer is `"hmac-verify"`
- Validate `Algorithm` is one of `HS256`/`HS384`/`HS512` (or empty, defaulting to `HS256`)
- Update all error messages in `Validate()` and `Build()` that enumerate supported normalizers to include `"hmac-verify"`.

---

### `internal/keep/config.go`

- Add `case "hmac-verify":` to `IdentityConfig.Validate()` switch — decodes `c.Config` (`map[string]any`) into `c.Normalizer.HMACVerify` via mapstructure, consistent with how `oidc-verify` decodes into `c.Normalizer.OIDCVerify`.
- Update `Strategy` field comment to list `"hmac-verify"` as a valid value.
- Add `"identity.config.secret"` to `SecretAllowlist` to enable `vault://` and `envvar://` support for the shared secret.
- **Update Production Posture Warning**: Update the warning at `config.go:142` to suggest `"oidc-verify" or "hmac-verify"` instead of only `"oidc-verify"`.

---

### `docs/AWS-bedrock-portcullis-integration.md`

- **Update Integration Guidance**: Refine the "Note for Portcullis Admins" (around line 48) to correctly describe the `hmac-verify` strategy and ensure it aligns with the finalized implementation requirements.

---

### `internal/keep/identity.go`

**Register `hmac-verify` normalizer in `init()`**, following the same pattern as the existing `oidc-verify` registration.

**Add `hmacVerifyingNormalizer` struct:**

| Field | Type | Notes |
|-------|------|-------|
| `method` | `jwt.SigningMethod` | Resolved from `Algorithm` at construction time. |
| `secret` | `[]byte` | Shared secret as a byte slice. |
| `issuer` | `string` | |
| `audiences` | `[]string` | |
| `allowMissingExpiry` | `bool` | |
| `maxTokenAgeSecs` | `int` | |

**Implement `Normalize()` on `hmacVerifyingNormalizer`:**

### Runtime Identity Contract

To ensure consistency with existing normalizers and the current Gate implementation, `hmac-verify` adheres to the following contract:

1.  **Source Type Handling**: 
    - **Accepted Sources**: The normalizer will process identities where `SourceType` is either `"oidc"` (required for current compatibility with Gate) or `"hmac"` (reserved for future use).
    - **Claim Stripping**: If `SourceType` is anything else (e.g., `"os"`), the normalizer **MUST** strip all directory claims and return a `Principal` containing only `UserID` and `SourceType`. This matches the behavior of `oidc-verify` at `internal/keep/identity.go:116`.
2.  **Token Requirement**: 
    - If `RawToken` is empty and `SourceType` is `"oidc"` or `"hmac"`, the normalizer **MUST** return a hard error (e.g., `"hmac identity missing raw token"`). This matches the behavior at `internal/keep/identity.go:127`.
3.  **Strict Algorithm Enforcement**: 
    - **Method Check**: The normalizer **MUST** reject any token whose signing method is not HMAC. This prevents RSA-to-HMAC key confusion attacks.
    - **Exact Algorithm Match**: The token's `alg` header **MUST** match the `Algorithm` configured in Keep **exactly** (e.g., if Keep is configured for `HS256`, a token using `HS384` or `HS512` **MUST** be rejected, even if the signature is valid). This ensures the implementation does not implicitly accept any HMAC variant in the family. A mismatch results in a hard error.
4.  **Signature Verification**:
    - If a `RawToken` is present but the signature verification fails (wrong secret or corrupted signature), the normalizer **MUST** return a hard error (e.g., `"hmac signature verification failed"`). This ensures that unverified identities are never allowed to proceed when a verification strategy is explicitly configured.
5.  **Claim Validation (Expiry/Age)**:
    - Violations of `exp` (expiry) or `max_token_age_secs` result in a **hard error**. Verification of the token's lifecycle is an authoritative check; an expired token is considered "not a valid identity."

### Principal Extraction
Extract claims into `shared.Principal` using the same field set as `oidc-verify`: `sub`, `email`, `name`, `groups`, `roles`, `department`, `amr`, `preferred_username`, `acr`, `exp`.

---

### `internal/keep/config.go`

- Add `case "hmac-verify":` to `IdentityConfig.Validate()` switch — decodes `c.Config` (`map[string]any`) into `c.Normalizer.HMACVerify` via mapstructure, consistent with how `oidc-verify` decodes into `c.Normalizer.OIDCVerify`.
- Update `Strategy` field comment to list `"hmac-verify"` as a valid value.
- Add `"identity.config.secret"` to `SecretAllowlist` to enable `vault://` and `envvar://` support for the shared secret.

---

### `internal/keep/config_test.go` & `internal/shared/identity/identity_test.go`

**Config-Layer Validation Tests:**
- `identity.strategy: "hmac-verify"` is accepted as a valid strategy.
- `identity.config.secret` is required when strategy is `"hmac-verify"`.
- `identity.config.algorithm` must be one of `"HS256"`, `"HS384"`, or `"HS512"` (or empty).
- `vault://` and `envvar://` URI resolution is permitted for `identity.config.secret`.
- Production mode correctly rejects `"passthrough"` but accepts both `"oidc-verify"` and `"hmac-verify"`.
- The posture report warning for `"passthrough"` correctly mentions both `"oidc-verify"` and `"hmac-verify"` as secure alternatives.

**Build-Path Tests:**
- `identity.Build()` correctly constructs an `*hmacVerifyingNormalizer` when configured.

---

### `internal/keep/identity_test.go`

**Normalizer Behavior (Table-driven tests):**

| Case | Expected |
|------|----------|
| Valid HS256 token | Correct `Principal` fields |
| Valid HS384 token | Correct `Principal` fields |
| Valid HS512 token | Correct `Principal` fields |
| Wrong secret | Error |
| Expired token | Error |
| Missing `exp`, `AllowMissingExpiry: false` | Error |
| Missing `exp`, `AllowMissingExpiry: true` | Success |
| RS256 token presented to HMAC normalizer | Error (Algorithm Mismatch) |
| HS512 token presented to HS256 config | Error (Algorithm Mismatch) |
| Malformed JWT string | Error |
| Non-HMAC SourceType | Stripped Principal |
| Issuer mismatch | Error |
| Audience mismatch | Error |
| Missing `sub` claim | Error |
| Token age exceeds `MaxTokenAgeSecs` | Error |
| Empty `Algorithm` field | HS256 used as default |


---

## Out of Scope

- Multi-secret / key rotation support (YAGNI — single secret is the correct scope for now)
- Changes to Gate, OPA policies, or docker configs
- `ARCHITECTURE.md` update — `hmac-verify` is an implementation of the existing `Normalizer` interface, not a new component

---

## Example Config

```yaml
identity:
  strategy: "hmac-verify"
  config:
    secret: "envvar://AGENTCORE_HMAC_SECRET"
    algorithm: "HS256"
    issuer: "amazonaws.com"
    audiences:
      - "portcullis-mcp"
    max_token_age_secs: 3600
```
