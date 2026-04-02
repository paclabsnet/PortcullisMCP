# Implementation Plan

## Task: Add mTLS support for Gate-to-Guard traffic — COMPLETED 2026-04-02

### Design decision (chosen: strict listener & auth segregation)

Guard serves two different clients with distinct trust profiles and **strictly separate network paths**:
- **Human Browser** (UI: `/approve`): Human-facing, standard TLS.
- **Gate Client** (API: `/token/*`, `/pending`): Machine-to-machine, mTLS or Bearer.

This strict split ensures that the "Rogue AI" threat is mitigated at the network layer: an agent cannot satisfy the mTLS/Machine-Auth requirements of the API port, and the UI is physically unavailable on that port.

#### Listeners (Required):
- `listen.ui_address`: Dedicated listener for the `/approve` UI.
- `listen.api_address`: Dedicated listener for Gate API calls.

#### Security Logic (Machine Auth Middleware):
Authentication is checked in this order for all requests on the API listener:
1. **mTLS**: If valid peer certificates are present (verified by the listener), access is granted.
2. **Bearer**: If a valid `Authorization: Bearer <token>` is provided, access is granted.
3. **Nag-ware**: If neither is present BUT `auth.allow_unauthenticated` is `true`, a `slog.Warn` is logged and access is granted (PoC/Dev mode).
4. **Fail**: Otherwise, return `401 Unauthorized`.

---

### Step 1 — Move shared TLS code to `internal/shared`

`buildServerTLS` lives in `internal/keep/server.go`, and `TLSConfig` lives in `internal/keep/config.go`. Both Keep and Guard need them, so move them to avoid duplication.

- Create `internal/shared/tlsutil/tlsutil.go`:
  - Move `TLSConfig` struct (fields: `Cert`, `Key`, `ClientCA`) from `internal/keep/config.go`
  - Move `buildServerTLS(cfg TLSConfig) (*tls.Config, error)` from `internal/keep/server.go`
- Update `internal/keep/config.go` and `internal/keep/server.go` to import and use `tlsutil.TLSConfig` and `tlsutil.BuildServerTLS` (capitalised for export)
- Update `internal/keep/server_mtls_test.go` to reference the moved types

---

### Step 2 — Guard server: Refactor for Strict Split

**Config changes** (`internal/guard/config.go`):

```yaml
listen:
  ui_address: "0.0.0.0:8444"
  ui_tls:
    cert: "/tls/guard-server.crt"
    key:  "/tls/guard-server.key"
  api_address: "0.0.0.0:8445"
  api_tls:
    cert: "/tls/guard-server.crt"
    key:  "/tls/guard-server.key"

auth:
  bearer_token: "..."
  allow_unauthenticated: false
  mtls:
    client_ca: "/tls/ca.crt"
```

- **Validation**:
  - Require both `ui_address` and `api_address`.
  - If `auth.allow_unauthenticated` is `false`, require either `bearer_token` or `mtls.client_ca`.
- **Startup**:
  - `Run()` spawns two distinct `http.Server` instances.
  - `uiMux`: Only `/approve`, `/healthz`, `/readyz`.
  - `apiMux`: `/token/*`, `/pending`, `/healthz`, `/readyz`.
  - **Note**: `/healthz` and `/readyz` routes on both listeners **must** use the same underlying handler methods (`s.handleHealthz`, `s.handleReadyz`) to ensure a single source of truth for process health while allowing independent listener verification.
  - **Readiness**: Implement atomic flags (e.g., `uiReady`, `apiReady`) in the `Server` struct. `handleReadyz` **must** return `503 Service Unavailable` unless **both** listeners are successfully bound and serving.
  - The `apiMux` server uses `auth.mtls.client_ca` to enforce `tls.RequireAndVerifyClientCert`.

---

### Step 3 — Gate client: Update for Dual Guard Ports

**Config changes** (`internal/gate/config.go`):

```yaml
guard:
  escalation_approval_endpoint: "https://guard.corp.com" # Required (UI)
  token_api_endpoint:           "https://guard.internal:8445" # Required (API)
  auth:
    bearer_token: "..."
    mtls:
      server_ca:   "~/.portcullis/tls/ca.crt"
      client_cert: "~/.portcullis/tls/gate-client.crt"
      client_key:  "~/.portcullis/tls/gate-client.key"
```

- **Validation**: Require both `escalation_approval_endpoint` and `token_api_endpoint`.
- **API Routing**: Update `NewGuardClient` to use the `token_api_endpoint` exclusively for all machine calls (polling, claiming, registering pending JWTs).
- **UI Routing**: Update `buildEscalationMessage` to exclusively use `escalation_approval_endpoint` for constructing the link shown to the agent and user.
- **Status Reporting**: Update the `portcullis_status` MCP tool to report both Guard endpoints, clearly distinguishing between the "Approval UI" and "Token API".

---

### Step 4 — New sandbox cert: Guard server cert

- Update `deploy/docker-sandbox/tls/gen_certs.go` to emit `guard-server.crt` / `.key`.
- SANs: `localhost`, `127.0.0.1`, `portcullis-guard`.

---

### Step 5 — Docker sandbox config updates

- `deploy/docker-sandbox/guard-demo.yaml`: Update to the new dual-listener and nested auth schema.
- `deploy/docker-sandbox/docker-compose.yml`: Expose both ports (8444, 8445) and mount TLS volume.

---

### Step 6 — Tests

- **Guard Server Auth Matrix** (`internal/guard/server_mtls_test.go`):
  - **mTLS Only**: Verify access is granted with valid peer cert; rejected without.
  - **Bearer Only**: Verify access is granted with valid `Authorization` header; rejected without.
  - **Auth Priority**: Verify access is granted when both are provided (mTLS takes precedence in logs).
  - **PoC Mode (Nag-ware)**: Verify access is granted with a `slog.Warn` when no auth is provided but `allow_unauthenticated: true`.
  - **Fail Closed**: Verify 401 Unauthorized when no auth is provided and `allow_unauthenticated: false`.
  - **Invalid Credentials**: Verify rejection for expired/untrusted certs and incorrect bearer tokens.

- **Guard Route Segregation**:
  - **UI Port Isolation**: Verify `/approve` works; `/token/*` and `/pending` return 404.
  - **API Port Isolation**: Verify `/token/*` and `/pending` work; `/approve` returns 404.
  - **Shared Routes**: Verify `/healthz` and `/readyz` work on both listeners.

- **Guard Config Validation**:
  - **Missing Listeners**: Verify failure if `ui_address` or `api_address` is omitted.
  - **Insecure Default**: Verify failure if `allow_unauthenticated: false` but no `bearer_token` or `mtls.client_ca` is configured.

- **Gate GuardClient** (`internal/gate/guardclient_test.go`):
  - **Strict Endpoint Use**: Verify machine calls (polling, claim) only target `token_api_endpoint`.
  - **Handshake Errors**: Verify clear error messages when the TLS handshake fails (e.g., untrusted CA).
  - **Auth Headers**: Verify Bearer token is correctly attached to API requests.

---

### Step 7 — Version bump

Increment `internal/version/version.go` to `0.3.7` (reflecting the significant architectural refactor).

---

### Files touched (summary)

| File | Change |
|------|--------|
| `internal/shared/tlsutil/tlsutil.go` | new — shared TLS helpers |
| `internal/keep/server.go` | update to use tlsutil |
| `internal/keep/server_mtls_test.go` | update for tlsutil type references |
| `internal/guard/config.go` | new strict Listen and Auth config structures |
| `internal/guard/config_test.go` | update for new Listen and Auth validation rules |
| `internal/guard/server.go` | dual-listener (uiSrv/apiSrv) implementation |
| `internal/guard/server_test.go` | update for dual-listener and auth config |
| `internal/guard/server_health_test.go` | update for cross-port readiness tests |
| `internal/guard/server_token_test.go` | update to target api_address |
| `internal/guard/server_validation_test.go` | update for new nested config validation |
| `internal/guard/server_mtls_test.go` | new tests for strict segregation and auth matrix |
| `internal/gate/config.go` | required nested guard.auth and endpoint config |
| `internal/gate/guardclient.go` | API-only communication in GuardClient |
| `internal/gate/server.go` | UI-only endpoint in escalation messages; update status tool |
| `deploy/docker-sandbox/tls/gen_certs.go` | add Guard server certs |
| `deploy/docker-sandbox/gate-demo.yaml` | update for dual-endpoint Guard config |
| `deploy/docker-sandbox/guard-demo.yaml` | update for dual-listener and nested auth |
| `deploy/docker-sandbox/docker-compose.yml` | expose port 8445 and mount TLS volume |
| `internal/version/version.go` | 0.3.7 |
