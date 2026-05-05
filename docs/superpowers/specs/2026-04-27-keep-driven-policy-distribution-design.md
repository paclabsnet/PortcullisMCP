# Design Specification: Keep-Driven Policy Distribution

## 1. Overview
Currently, the `portcullis-localfs` tool policy (workspace, forbidden paths, strategy) is hardcoded in the Portcullis-Gate YAML configuration. This design introduces a "Keep-driven" model where Gate can dynamically fetch this configuration from Portcullis-Keep at startup and refresh it periodically. Keep, in turn, retrieves the specific JSON configuration from a Policy Decision Point (PDP) like OPA.

This mechanism is designed to be generic, allowing other MCP tool configurations to be distributed via Keep in the future.

## 2. Architecture

### 2.1. Data Flow
1.  **Gate Initialization:** If a tool (e.g., `portcullis-localfs`) is configured with `rules.source: keep`, Gate initiates a request to Keep.
2.  **Keep Request:** Gate calls `GET /config/{resource}` (e.g., `GET /config/portcullis-localfs`) on Keep, providing its standard authorization bearer token.
3.  **Keep -> PDP:** Keep forwards the request to the PDP configured in `gate_static_policy`. It sends the following input:
    ```json
    { "input": { "resource": "{resource}" } }
    ```
4.  **PDP Response:** The PDP (e.g., OPA) returns a JSON result representing the specific configuration for that resource.
5.  **Keep -> Gate:** Keep returns the raw `result` from OPA back to Gate.
6.  **Gate Configuration:** Gate **MUST** validate the received JSON schema against the expected tool configuration structure (e.g., ensuring `workspace`, `forbidden`, and `strategy` blocks are present and valid) **before** unmarshaling into operational data structures.

### 2.2. Failure Handling (at Gate)

Degraded mode is **fail-closed**: any tool whose `rules.source` is `keep` will **deny all requests** until its first successful policy fetch. Gate starts globally; only the affected tools are denied — tools configured with `source: local` are unaffected.

-   **Keep Unreachable at Startup:** Affected tools immediately deny requests. Gate retries in the background until a valid policy is received.
-   **Keep Timeout/Error (with Cache):** If `on_fetch_failure: cached` (default) and a valid in-memory policy exists, reuse the last known good policy and **remain in a Healthy state**. If no in-memory cache exists (e.g., first fetch fails), the tool MUST remain in or transition to a Degraded state and deny all requests. Cache is **memory-only** — it does not survive a restart.
-   **Invalid JSON / Schema Violation:** Log a descriptive error and discard the response. If a valid cache exists, continue using it and remain Healthy. If no cache exists, transition to Degraded and deny all requests.
-   **Recovery/Transition:** A tool only enters Degraded mode if it lacks a valid policy (initial fetch failure or cache-less error). Once a valid policy is successfully fetched and validated, the tool transitions to or remains in a Healthy state.

## 3. Configuration Changes

### 3.1. Portcullis-Keep (`keep.yaml`)
```yaml
responsibility:
  # Runtime decision policy
  policy:
    strategy: "opa"
    config:
      endpoint: "http://opa:8181/v1/data/portcullis/tabular/decision"
  
  # Static configuration distribution policy
  gate_static_policy:
    strategy: "opa"
    config:
      endpoint: "http://opa:8181/v1/data/portcullis/gate_static_policy"
```

### 3.2. Portcullis-Gate (`gate.yaml`)
```yaml
responsibility:
  tools:
    portcullis-localfs:
      enabled: true
      rules:
        source: "keep"
        ttl: 3600               # seconds
        on_fetch_failure: "cached" # default; options: "cached" | "fail"
```

## 4. Components

### 4.1. Keep Server (`internal/keep`)
-   **`Config` Struct:** Add `GateStaticPolicy` (containing `PolicyConfig` and `Allowlist []string`) to `ResponsibilityConfig`.
-   **`Server` Struct:** Initialize a separate PDP client for `gateStaticPDP`.
-   **Handlers:** Add `handleGetConfig(w, r)` for `GET /config/{resource}`.
    -   Requires valid bearer token (existing `authMiddleware`). No per-caller resource-level authorization is performed.
    -   Validates that `{resource}` is present in the `allowlist`; reject with `403 Forbidden` and log a warning if not.
    -   Calls `gateStaticPDP.GetStaticPolicy(ctx, resource)`.

### 4.2. Gate Server (`internal/gate`)
-   **`Config` Struct:**
    -   Update `LocalFSConfig` with `Rules LocalFSRulesConfig`.
    -   Implement `LocalFSRulesConfig` with defaults: `source="local"`, `ttl=3600` (seconds), `on_fetch_failure="cached"`.
-   **`Forwarder`:** Add `GetStaticPolicy(ctx, resource)` to the interface and HTTP implementation.
-   **`Gate` Lifecycle:**
    -   During `New()`, if `source: keep`, trigger an initial async fetch.
    -   Implement a background goroutine for refreshing policies based on `TTL`.
    -   Provide status updates to `StateMachine` for degraded mode tracking.

### 4.3. LocalFS Tool (`internal/gate/localfs`)
-   Implement a `UpdatePolicy(Workspace, Forbidden, Strategy)` method to allow dynamic reconfiguration.
-   **Thread Safety:** The swapping of internal policy structures MUST be protected by a `sync.RWMutex` (or similar concurrency primitive) to ensure that tool calls in progress are not corrupted by a concurrent policy refresh.

## 5. Security Considerations
-   **Least Privilege:** Keep only fetches config from the PDP for explicitly allowlisted resource names; arbitrary resource probing is rejected server-side before the PDP is consulted.
-   **Authorization:** The `/config` endpoint is protected by the same bearer token mechanism as other Gate-to-Keep communication. No per-caller resource-level authorization is required.
-   **Validation:** Gate MUST perform strict schema validation on the returned JSON before applying it. Validation failures are fail-closed — the tool denies requests rather than falling back to a permissive default.
-   **Integrity:** Background refreshes apply the new policy atomically via write-lock swap only after full validation succeeds; concurrent in-flight tool requests are unaffected.
-   **Fail-Closed Guarantee:** No tool with `source: keep` will operate without a successfully validated policy. Degraded state, cache absence, and validation errors all result in request denial for the affected tool.
