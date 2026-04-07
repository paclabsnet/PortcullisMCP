# mTLS Setup: Gate, Keep and Guard

## Gate-to-Keep Authentication

Portcullis-Gate talks to Portcullis-Keep over HTTPS. By default a shared bearer
token is sufficient, but in production deployments mutual TLS (mTLS) is the
recommended authentication mechanism. With mTLS, both sides present X.509
certificates, so there is no shared secret to rotate or leak.

This guide walks through generating the certificates and writing the
configuration for both components.

---

### How it works

During the TLS handshake:

1. Keep presents its server certificate to Gate (standard TLS).
2. Keep also requests a client certificate from Gate (the "mutual" part).
3. Gate presents its client certificate, which Keep verifies against a
   configured CA.
4. If verification passes, the connection is established and auth is satisfied
   by the certificate — no bearer token is needed.

The relevant config fields are:

| Component | Config path | What it does |
|-----------|-------------|--------------|
| Keep | `server.endpoints.main.tls.cert` | Keep's server certificate |
| Keep | `server.endpoints.main.tls.key` | Private key for the cert above |
| Keep | `server.endpoints.main.tls.client_ca` | CA that signed Gate's client cert; **enables mTLS** |
| Keep | `server.endpoints.main.auth.type: mtls` | Declares the cert as the auth mechanism |
| Gate | `peers.keep.auth.type: mtls` | Tells Gate to present a client cert |
| Gate | `peers.keep.auth.credentials.cert` | Gate's client certificate |
| Gate | `peers.keep.auth.credentials.key` | Private key for Gate's client cert |
| Gate | `peers.keep.auth.credentials.server_ca` | (Optional) CA to trust for Keep's server cert, if private |

---

### Step 1: Generate the certificates

The simplest production setup uses two CAs: one for Keep's server identity and
one for Gate's client identity. You can use the same CA for both, but separate
CAs give you tighter control over what can connect.

The commands below use `openssl`. Adjust key sizes and validity periods to match
your organisation's policy.

#### 1a. CA for Gate's client certificates

```bash
# Create the Gate client CA key and self-signed cert
openssl genrsa -out gate-ca.key 4096
openssl req -x509 -new -nodes \
  -key gate-ca.key \
  -sha256 -days 3650 \
  -subj "/CN=Portcullis Gate CA" \
  -out gate-ca.crt
```

#### 1b. Keep's server certificate

```bash
# Create Keep's server key and a CSR
openssl genrsa -out keep.key 4096
openssl req -new \
  -key keep.key \
  -subj "/CN=keep.internal.example.com" \
  -out keep.csr

# Sign it with your internal CA (or self-sign for testing)
openssl x509 -req \
  -in keep.csr \
  -CA your-internal-ca.crt \
  -CAkey your-internal-ca.key \
  -CAcreateserial \
  -days 825 -sha256 \
  -out keep.crt
```

#### 1c. Gate's client certificate

```bash
# Create Gate's client key and CSR
openssl genrsa -out gate-client.key 4096
openssl req -new \
  -key gate-client.key \
  -subj "/CN=portcullis-gate" \
  -out gate-client.csr

# Sign it with the Gate client CA from step 1a
openssl x509 -req \
  -in gate-client.csr \
  -CA gate-ca.crt \
  -CAkey gate-ca.key \
  -CAcreateserial \
  -days 825 -sha256 \
  -out gate-client.crt
```

#### Certificate placement

| File | Where it goes |
|------|---------------|
| `keep.crt` + `keep.key` | Server running Keep (`/etc/portcullis/`) |
| `gate-ca.crt` | Server running Keep (`/etc/portcullis/`) |
| `gate-client.crt` + `gate-client.key` | Machine running Gate (`~/.portcullis/`) |
| `your-internal-ca.crt` | Machine running Gate (if Keep's cert is not in the system CA store) |

---

### Step 2: Configure Keep

```yaml
# keep.yaml
mode: production

server:
  endpoints:
    main:
      listen: "0.0.0.0:8443"
      tls:
        cert: "/etc/portcullis/keep.crt"
        key:  "/etc/portcullis/keep.key"
        # Setting client_ca enables mTLS. Gate must present a cert signed by
        # this CA or the connection will be rejected at the TLS layer.
        client_ca: "/etc/portcullis/gate-ca.crt"
      auth:
        # "mtls" means the verified client certificate satisfies authentication.
        # Remove this and use "bearer" if you want belt-and-suspenders (both
        # a valid cert AND a token required).
        type: "mtls"

identity:
  strategy: "oidc-verify"
  config:
    issuer: "https://login.microsoftonline.com/${AZURE_TENANT_ID}/v2.0"
    jwks_url: "https://login.microsoftonline.com/${AZURE_TENANT_ID}/discovery/v2.0/keys"

peers:
  guard:
    endpoints:
      approval_ui: "https://guard.internal.example.com"
      token_api:   "https://guard-api.internal.example.com"

responsibility:
  policy:
    strategy: "opa"
    config:
      endpoint: "http://opa.internal.example.com:8181/v1/data/portcullis/tabular/decision"

  mcp_backends:
    - name: "enterprise-api"
      type: "http"
      url: "https://mcp-api.internal.example.com/mcp"

  issuance:
    signing_key: "envvar://KEEP_SIGNING_KEY"
    ttl: 3600

  workflow:
    strategy: "url"
    config:
      endpoints:
        approval_ui: "https://guard.internal.example.com"

  admin:
    token: "envvar://KEEP_ADMIN_TOKEN"

operations:
  storage:
    backend: "memory"
  telemetry:
    exporter: "noop"
    service_name: "portcullis-keep"
  logging:
    level: "info"
    format: "json"
```

---

### Step 3: Configure Gate

```yaml
# gate.yaml
mode: production

server:
  endpoints:
    management_ui:
      listen: "localhost:7777"
      auth:
        type: "none"

identity:
  strategy: "oidc-file"
  config:
    token_file: "~/.portcullis/oidc-token"

peers:
  keep:
    endpoint: "https://keep.internal.example.com:8443"
    auth:
      type: "mtls"
      credentials:
        # Gate's client cert and key, signed by the gate-ca.crt Keep trusts.
        cert: "~/.portcullis/gate-client.crt"
        key:  "~/.portcullis/gate-client.key"
        # Only needed if Keep's server cert is signed by a private CA that is
        # not in the system CA store on this machine.
        # server_ca: "~/.portcullis/internal-ca.crt"

  guard:
    endpoints:
      approval_ui: "https://guard.internal.example.com"
      token_api:   "https://guard-api.internal.example.com"
    auth:
      type: "bearer"
      credentials:
        bearer_token: "envvar://GUARD_BEARER_TOKEN"

responsibility:
  workspace:
    directory: "~/sandbox"
  escalation:
    strategy: "proactive"
    poll_interval: 60
    token_store: "~/.portcullis/tokens.json"

operations:
  telemetry:
    exporter: "noop"
    service_name: "portcullis-gate"
  logging:
    level: "info"
    format: "text"
```

---

## Gate-to-Guard mTLS

Guard exposes two endpoints:

- `approval_ui` — browser-facing approval interface. This is used by human
  approvers, not by Gate, so mTLS is not appropriate here. Secure it with an
  SSO proxy instead (see `docs/guard-sso-proxy.md`).
- `token_api` — machine-facing API that Gate calls to poll for and redeem
  approved escalation tokens. This is the endpoint that should use mTLS.

### How it works

The flow is the same as Gate→Keep: Gate presents a client certificate when
connecting to Guard's `token_api`, and Guard verifies it against a configured
CA. The difference is that Gate and Guard each have their own independent
client CA, so you can revoke Gate's access to Keep and Guard independently.

### Step 1: Generate certificates for the Guard side

You need a client certificate for Gate to present to Guard. You can reuse the
same Gate client CA from the Keep section, or create a separate one for Guard.
Using a separate CA is recommended — it limits the blast radius if either CA
is compromised.

```bash
# Optional: create a separate CA for Gate's client cert presented to Guard
openssl genrsa -out gate-guard-ca.key 4096
openssl req -x509 -new -nodes \
  -key gate-guard-ca.key \
  -sha256 -days 3650 \
  -subj "/CN=Portcullis Gate-Guard CA" \
  -out gate-guard-ca.crt

# Gate's client cert for Guard (sign with whichever CA Guard will trust)
openssl genrsa -out gate-guard-client.key 4096
openssl req -new \
  -key gate-guard-client.key \
  -subj "/CN=portcullis-gate" \
  -out gate-guard-client.csr

openssl x509 -req \
  -in gate-guard-client.csr \
  -CA gate-guard-ca.crt \
  -CAkey gate-guard-ca.key \
  -CAcreateserial \
  -days 825 -sha256 \
  -out gate-guard-client.crt
```

Guard also needs a server certificate for its `token_api` endpoint if it does
not already have one:

```bash
openssl genrsa -out guard-token-api.key 4096
openssl req -new \
  -key guard-token-api.key \
  -subj "/CN=guard-api.internal.example.com" \
  -out guard-token-api.csr

openssl x509 -req \
  -in guard-token-api.csr \
  -CA your-internal-ca.crt \
  -CAkey your-internal-ca.key \
  -CAcreateserial \
  -days 825 -sha256 \
  -out guard-token-api.crt
```

### Step 2: Configure Guard

Only the `token_api` endpoint needs `client_ca`. The `approval_ui` endpoint
is left with standard TLS (no client cert requirement):

```yaml
# guard.yaml
mode: production

server:
  endpoints:
    approval_ui:
      listen: "0.0.0.0:8444"
      tls:
        cert: "/etc/portcullis/guard-ui.crt"
        key:  "/etc/portcullis/guard-ui.key"
        # No client_ca here — this endpoint is browser-facing.
      # No auth block. The approval_ui has no auth middleware; access control
      # is provided by the signed JWT embedded in the approval link URL.
      # To restrict network-level access, use an SSO proxy (see docs/guard-sso-proxy.md).

    token_api:
      listen: "0.0.0.0:8445"
      tls:
        cert: "/etc/portcullis/guard-token-api.crt"
        key:  "/etc/portcullis/guard-token-api.key"
        # Setting client_ca enables mTLS on this endpoint.
        client_ca: "/etc/portcullis/gate-guard-ca.crt"
      auth:
        type: "mtls"

responsibility:
  issuance:
    approval_request_verification_key: "envvar://KEEP_SIGNING_KEY"
    signing_key: "envvar://GUARD_SIGNING_KEY"
    token_ttl: 86400

  interface:
    templates: "/etc/portcullis/guard/templates"
    gate_management_port: 7777

operations:
  storage:
    backend: "memory"
  telemetry:
    exporter: "noop"
    service_name: "portcullis-guard"
  logging:
    level: "info"
    format: "json"
```

### Step 3: Update Gate

Change `peers.guard.auth` from `bearer` to `mtls` and point it at the client
cert you generated for the Guard connection:

```yaml
peers:
  keep:
    endpoint: "https://keep.internal.example.com:8443"
    auth:
      type: "mtls"
      credentials:
        cert: "~/.portcullis/gate-client.crt"
        key:  "~/.portcullis/gate-client.key"

  guard:
    endpoints:
      approval_ui: "https://guard.internal.example.com:8444"
      token_api:   "https://guard-api.internal.example.com:8445"
    auth:
      type: "mtls"
      credentials:
        # A separate client cert/key pair for the Guard connection.
        cert: "~/.portcullis/gate-guard-client.crt"
        key:  "~/.portcullis/gate-guard-client.key"
        # Only needed if Guard's token_api cert is signed by a private CA.
        # server_ca: "~/.portcullis/internal-ca.crt"
```

Note that `auth` under `peers.guard` applies to the `token_api` endpoint only.
Gate never makes machine-to-machine requests to `approval_ui`.

---

## Verification

After starting Keep and Guard with the new configurations, use `openssl s_client`
to confirm mTLS is working end-to-end on both connections:

```bash
# --- Gate-to-Keep ---

# Without client cert — Keep should reject at TLS layer
openssl s_client \
  -connect keep.internal.example.com:8443 \
  -CAfile /path/to/internal-ca.crt

# With Gate's client cert — should succeed
openssl s_client \
  -connect keep.internal.example.com:8443 \
  -CAfile /path/to/internal-ca.crt \
  -cert ~/.portcullis/gate-client.crt \
  -key  ~/.portcullis/gate-client.key

# --- Gate-to-Guard (token_api only) ---

# Without client cert — Guard should reject at TLS layer
openssl s_client \
  -connect guard-api.internal.example.com:8445 \
  -CAfile /path/to/internal-ca.crt

# With Gate's Guard client cert — should succeed
openssl s_client \
  -connect guard-api.internal.example.com:8445 \
  -CAfile /path/to/internal-ca.crt \
  -cert ~/.portcullis/gate-guard-client.crt \
  -key  ~/.portcullis/gate-guard-client.key
```

In both Keep's and Guard's logs you should see the peer CN (`portcullis-gate`)
recorded on every authenticated request.

---

## Common mistakes

**`client_ca` is set but `auth.type` is still `bearer`.**
The server will enforce the client cert at the TLS layer, but then also demand a
bearer token and reject the request. Set `auth.type: mtls` to let the cert
satisfy authentication on its own.

**Gate's cert was signed by the wrong CA.**
The `client_ca` on each endpoint must be the CA that signed Gate's client cert
for that specific connection — not the CA that signed the server's own cert.
These are deliberately separate chains.

**`server_ca` omitted when the server uses a private CA.**
If a server cert is signed by a private CA not in the system CA store on the
Gate machine, Gate will refuse to connect. Set `server_ca` under the relevant
`peers.*.auth.credentials` to the path of that CA certificate.

**Using the same client cert for Keep and Guard.**
This works, but means a single compromised cert loses access to both services.
Separate client certs (and optionally separate client CAs) are recommended so
each connection can be revoked independently.

**Attempting to set `client_ca` on `approval_ui`.**
The approval UI is browser-facing. Browsers do not present client certificates
by default. Leave `approval_ui` without `client_ca` and secure it at the
application layer with an SSO proxy.
