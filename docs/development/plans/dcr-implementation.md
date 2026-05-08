# Dynamic Client Registration (DCR) Implementation Plan

## Objective
Implement RFC 7591 Dynamic Client Registration (DCR) in the `keep` service to allow Portcullis to automatically register itself as a client with third-party Identity Providers (IdPs) just-in-time, prior to initiating a user OAuth flow.

## Key Files & Context
- `internal/keep/config.go`: Requires updates to support DCR configuration.
- `internal/keep/credentials_store.go`: Requires updates to the `clientReg` struct to store additional metadata returned by the DCR endpoint.
- `internal/keep/dcr.go` (New File): Contains the RFC 7591 client implementation.
- `internal/keep/router.go` & `internal/keep/server.go`: The integration point where DCR is triggered before starting an OAuth flow.

## Proposed Solution

### 1. Configuration Updates (`internal/keep/config.go`)
Introduce a `BackendDCR` struct and embed it within `BackendOAuth`.

```go
// BackendDCR configures RFC 7591 Dynamic Client Registration for a backend.
type BackendDCR struct {
	// Enabled determines if DCR should be attempted when no client registration exists.
	Enabled bool `yaml:"enabled"`
	// RegistrationEndpoint is the IdP's RFC 7591 endpoint.
	RegistrationEndpoint string `yaml:"registration_endpoint"`
	// InitialAccessToken (IAT) is the Bearer token used to authenticate the registration request (optional).
	InitialAccessToken string `yaml:"initial_access_token"`
	// SoftwareStatement is a JWT asserting client metadata (optional).
	SoftwareStatement string `yaml:"software_statement"`
	// ClientName is the human-readable name to register with the IdP.
	ClientName string `yaml:"client_name"`
	// Timeout is the maximum time to wait for the DCR request to complete (optional, defaults to 10s).
	Timeout time.Duration `yaml:"timeout"`
	// FailureCacheTTL is the duration to cache a DCR failure (optional, defaults to 5m).
	FailureCacheTTL time.Duration `yaml:"failure_cache_ttl"`
}

type BackendOAuth struct {
	// ... existing fields ...
	// DCR configures dynamic client registration. If enabled, ClientID can be empty.
	DCR BackendDCR `yaml:"dcr"`
}
```

### 2. Update Credentials Store (`internal/keep/credentials_store.go`)
Update the existing `clientReg` struct and the `CredentialsStore` interface.

```go
// clientReg holds dynamic client registration credentials for a backend.
type clientReg struct {
	ClientID                string `json:"client_id"`
	ClientSecret            string `json:"client_secret,omitempty"`
	ClientSecretExpiresAt   int64  `json:"client_secret_expires_at,omitempty"` // Unix timestamp
	TokenEndpointAuthMethod string `json:"token_endpoint_auth_method,omitempty"`
	Scopes                  string `json:"scope,omitempty"`
}
```

**Rationale for Expiration Handling**:
- **Automatic Recovery**: RFC 7591 secrets can expire. By tracking `ClientSecretExpiresAt`, the system can detect expired credentials and automatically re-trigger the DCR flow instead of getting stuck in a permanent failure state.
- **Proactive Refresh**: Just like access tokens, client secrets can be refreshed proactively before they expire to avoid runtime disruption.

**Rationale for Scope Storage**:
- **Protocol Verification**: Allows the system to immediately confirm if mandatory scopes (e.g., `openid`) were granted by the IdP policy.
- **Auth URL Optimization**: Enables the system to intersect the statically configured scopes with the actually granted scopes, preventing "Invalid Scope" errors during the user's OAuth redirect flow.
- **Audit & Traceability**: Provides a clear record of the dynamic client's capabilities for troubleshooting and security auditing.

```go
type CredentialsStore interface {
	// ... existing methods ...
	GetClientReg(ctx context.Context, backend string) (*clientReg, error)
	// SetClientRegNX atomically sets the registration if it doesn't already exist.
	// Returns (true, nil) if set, (false, nil) if it already existed.
	SetClientRegNX(ctx context.Context, backend string, reg *clientReg) (bool, error)
	// LockDCR acquires a distributed lock for the specified backend.
	// Returns an unlock function and nil on success.
	LockDCR(ctx context.Context, backend string) (func(), error)
	// GetDCRFailure returns the error message of a recent failed DCR attempt, if still within the failure window.
	GetDCRFailure(ctx context.Context, backend string) (string, error)
	// SetDCRFailure records a failed DCR attempt and its reason, to be cached for the specified duration.
	SetDCRFailure(ctx context.Context, backend string, reason string, ttl time.Duration) error
}
```

**Implementation Details**:
- **Atomic Storage**:
  - The `CredentialsStore` MUST treat the entire `clientReg` record as a single atomic unit to prevent "Read-Under-Update" issues (where a reader might see a mismatched `client_id` and `client_secret`).
  - Redis: Store the entire record as a single JSON blob under a single key.
  - Memory: Use a `sync.RWMutex` to protect access to the registration map and perform atomic pointer swaps for updates.
- **Distributed Locking**:
  - Redis: Use `SET dcr_lock:{backend} {randomValue} NX EX {timeout}` to implement the lock.
  - Memory: A simple `sync.Mutex` per backend.
- **IAT Protection**: The distributed lock ensures that only ONE instance globally attempts DCR, preventing single-use Initial Access Tokens from being invalidated by concurrent requests.

**Implementation Details**:
- **Key Naming**: 
  - Redis: `dcr_fail:{backendName}`
  - Memory: A new `dcrFailures map[string]*dcrFailureEntry` where the entry contains the reason and an expiry timestamp.
- **Negative Caching Logic**:
  - Before attempting DCR, the system calls `GetDCRFailure`. 
  - If a non-empty string is returned, the OAuth flow is aborted immediately with that reason.
  - If DCR fails, `SetDCRFailure` is called with a default TTL of 5 minutes.

### 3. Implement DCR Client (`internal/keep/dcr.go`)
Create a new file `internal/keep/dcr.go` exposing a function to perform the registration:

```go
package keep

import (
	"context"
	"net/http"
	"time"
)

// RegisterDynamicClient performs an RFC 7591 client registration and returns the registration details.
func RegisterDynamicClient(ctx context.Context, client *http.Client, oauthCfg *BackendOAuth) (*clientReg, error) {
	// 0. Context Timeout Handling:
	//    - In 'dcr.go', if 'oauthCfg.DCR.Timeout' is 0, default it to 10*time.Second.
	//    - Derive a timed context from 'ctx' using the MINIMUM of the parent context's deadline and this timeout.
	//    - Ensure the registration request respects this final deadline to prevent hanging.
	// 1. Construct the Client Metadata JSON payload (RFC 7591 section 2):
	//    - redirect_uris: Must exactly match oauthCfg.CallbackURL.
	//    - client_name: From oauthCfg.DCR.ClientName.
	//    - response_types: ["code"]
	//    - grant_types: ["authorization_code", "refresh_token"] (if StoreRefreshTokens is true).
	//    - token_endpoint_auth_method: Default to "client_secret_basic" (or "client_secret_post" if needed).
	//    - scope: Space-separated list from oauthCfg.Scopes to register default scopes.
	// 2. Attach InitialAccessToken (as Bearer header) or SoftwareStatement (in JSON payload) if configured.
	// 3. POST to oauthCfg.DCR.RegistrationEndpoint.
	// 4. Parse the JSON response containing client_id, client_secret, token_endpoint_auth_method, and scope.
	// 5. Scope Validation & Logging:
	//    - Compare the returned 'scope' string with the requested 'oauthCfg.Scopes'.
	//    - If the IdP returned fewer or different scopes, issue a WARN log but proceed.
	// 6. Return a populated *clientReg.
}
```

### 4. Integration into OAuth Flow (`internal/keep/router.go` or `server.go`)
Update the code path that initiates the OAuth flow (e.g., `tryStartOAuthFlow` in `router.go`).

**Just-In-Time (JIT) Discovery Validation**:
- During the `resolveOAuthEndpoints` call (which performing JIT OIDC discovery), if `DCR.Enabled` is `true`, the system MUST verify that the discovered metadata contains a `registration_endpoint`.
- **Protocol Mismatch Handling**:
  - If the `registration_endpoint` is missing from the discovered metadata, the flow MUST fail fast. The **Administrator** should see a clear error: *"DCR required but not supported by IdP (missing registration_endpoint)."*
  - **Explicit Error Type**: `RegisterDynamicClient` will return a sentinel error `ErrDCRNotSupported` if the registration attempt returns an HTTP **404 (Not Found)** or **405 (Method Not Allowed)**.
  - If the caller receives `ErrDCRNotSupported`, it MUST log a specific instruction for the **Administrator**: *"DCR is enabled but the IdP does not support RFC 7591. Please register the client manually and provide a static client_id."*
  - These "Protocol Not Supported" failures MUST use a hardcoded extended negative cache duration (e.g., 1 hour, defined as `dcrProtocolMismatchTTL`).

Before constructing the authorization URL:
1. Call `credentialsStore.GetClientReg(ctx, backendName)`.
2. **Expiration Check**: 
   - If `clientReg != nil` and `clientReg.ClientSecretExpiresAt > 0`:
     - If the secret is expired (or within the `RefreshWindowSecs` buffer), treat `clientReg` as `nil` to trigger re-registration.
3. **Scope Intersection**: 
   - If `clientReg != nil` and `clientReg.Scopes != ""` (Dynamic Client):
     - The system MUST intersect the configured `oauthCfg.Scopes` with the `clientReg.Scopes` (IdP-granted list).
     - The resulting subset is used in the `buildAuthURL` call. This prevents "Invalid Scope" errors if the IdP granted fewer scopes than requested during DCR.
   - If `clientReg == nil` (Static Client):
     - Use `oauthCfg.Scopes` directly.
4. If `clientReg != nil`, use `clientReg.ClientID`.
4. If `clientReg == nil` and `oauthCfg.ClientID` is statically configured, use `oauthCfg.ClientID`.
5. If `clientReg == nil` and `oauthCfg.DCR.Enabled` is true:
   - **Concurrency Handling (Thundering Herd Prevention)**: 
     - Use a `golang.org/x/sync/singleflight` Group (keyed by `backendName`) to coordinate registration attempts. 
     - **Ownership**: The `singleflight.Group` will be a field within a dedicated `DCRManager` or integrated directly into the `CredentialsStore` implementations to ensure clean lifecycle management.
     - This ensures that if multiple requests trigger OAuth simultaneously on a *single instance*, only one performs the DCR request.
   - Inside the `singleflight` function's execution block:
     - **Local Cache Re-check**: Verify the cache again (`GetClientReg`). Return if found.
     - **Negative Cache Check**: Call `GetDCRFailure`. If a failure is cached, abort the OAuth flow immediately with that reason.
     - **Global Coordination**: Call `credentialsStore.LockDCR(ctx, backendName)` to acquire the distributed lock. This protects single-use IATs by ensuring only one instance globally communicates with the IdP.
     - **Critical Section** (while lock is held, using `defer unlock()`):
       - **Global Cache Re-check**: Verify the cache **one final time** (`GetClientReg`) to see if the lock-winner from a concurrent instance already persisted the result. Return if found.
       - **DCR HTTP Call**: Call `dcr.RegisterDynamicClient()`.
       - **Error Handling & Retry Prevention**: 
         - If `RegisterDynamicClient` fails, the system MUST **fail fast**.
         - **Storage**: The "DCR Failure" state MUST be stored in the `CredentialsStore` via `SetDCRFailure`.
         - A failed registration attempt should be cached for a short period:
           - **Standard Failure**: `failure_cache_ttl` (defaults to 5 minutes).
           - **Protocol Mismatch (`ErrDCRNotSupported`)**: `dcrProtocolMismatchTTL` (hardcoded 1 hour).
         - Return the error.
       - **Atomic Storage**: 
         - If successful, call `credentialsStore.SetClientRegNX(ctx, backendName, reg)`.
         - If `SetClientRegNX` returns `false` (meaning another instance won the registration race despite the lock, or due to a lock timeout/split-brain):
           - Discard the local registration result.
           - Re-fetch the winner's credentials using `GetClientReg(ctx, backendName)`.
           - (Future) Consider implementing RFC 7592 client rotation/management for cleanup of abandoned IDs.
         - Return the acquired `clientReg`.
   - Use the `client_id` from the successfully acquired (or returned) `clientReg`.
   - **Manual Invalidation**: In the event of a persistent DCR failure (e.g., due to misconfiguration), the **Administrator** can manually clear the negative cache:
     - **Redis**: Execute `DEL dcr_fail:{backendName}`.
     - **Memory**: Requires a service restart (state is ephemeral).
6. **Token Exchange & Refresh Integration**:
   - Update `server.go`'s `exchangeOAuthCode` and `router.go`'s `refreshOAuthToken` to fetch the client credentials via `GetClientReg(ctx, backendName)` instead of strictly relying on `BackendOAuth.ClientID`.
   - **Client Authentication**: If the IdP returned a `client_secret` during DCR, it MUST be securely retrieved from the `CredentialsStore` and used to authenticate against the token endpoint.
   - **Auth Method Support**: The implementation MUST support the following RFC 7591 `token_endpoint_auth_method` values:
     - `client_secret_basic` (Default/Fallback): Credentials sent in the `Authorization: Basic` header.
     - `client_secret_post`: Credentials sent in the request body.
     - `none`: Used for public clients; no secret is sent.
   - **Fallback Mechanism**: If the IdP returns an empty or unknown `token_endpoint_auth_method`, the system MUST fallback to `client_secret_basic` for maximum compatibility.
   - The token endpoint request MUST respect the `TokenEndpointAuthMethod` stored in the `clientReg`.

### Alternatives Considered
- **Pre-flight Job / CLI tool:** Doing DCR manually via CLI or a separate cron job. *Rejected* because Portcullis aims for zero-touch configuration where possible, and just-in-time registration fits the dynamic nature of MCP backends.

## Verification & Testing
1. **Unit Tests (`dcr_test.go`)**: 
   - Mock an HTTP server responding with RFC 7591 success payload.
   - Explicitly mock RFC 7591 error responses (e.g., `{"error":"invalid_software_statement"}`) and verify the error is surfaced correctly.
   - Verify IAT Bearer token and Software Statement injection.
2. **Credentials Store Tests (`credentials_store_test.go`)**:
   - Add tests specifically verifying that the `client_secret` and `token_endpoint_auth_method` are persisted and retrieved correctly across both memory and Redis implementations.
3. **Integration Tests (`router_test.go` / `server_test.go`)**:
   - Verify that `tryStartOAuthFlow` triggers DCR when enabled and no client exists.
   - Verify that subsequent calls use the cached `clientReg` from the `CredentialsStore` and do not trigger DCR again.
   - Verify that token exchange/refresh correctly uses the retrieved `client_secret` and authenticates according to the `token_endpoint_auth_method`.
4. **End-to-End**: 
   - Test against a local **Keycloak** instance configured to require DCR. (Note: Keycloak is preferred for this E2E test over Dex, as Keycloak provides robust, out-of-the-box support for RFC 7591 Dynamic Client Registration).
   - **Documentation**: The test harness MUST include a guide (e.g., `internal/keep/testdata/keycloak_setup.md`) detailing the exact Keycloak settings required to enable DCR, including:
     - Realm-level "Client Registration" policies.
     - "Initial Access Token" (IAT) generation steps.
     - Software Statement requirements (if enforced by the test scenario).