# Securing Portcullis-Guard with an SSO Proxy

## The threat: agent self-approval

The Guard approval page (`/approve`) is intentionally unauthenticated — a human user is meant to open the link their
agent provides, review the request, and click Approve. However, a rogue or compromised agent that has access to the
approval URL, and the ability to call HTTP POST could fetch the page itself, and POST an approval without the user ever
seeing it.

**Mitigation:** place Guard behind a corporate identity-aware proxy that enforces browser-based SSO authentication
before any request reaches Guard. The proxy gates human access at the network layer; the agent cannot satisfy an
interactive SSO challenge and therefore cannot self-approve.

This is the recommended production deployment pattern. Guard itself requires no code changes.

---

## How it works

```
Agent (cannot authenticate)          Human browser
        |                                   |
        | GET /approve?jti=...              | GET /approve?jti=...
        v                                   v
  [ SSO Proxy ]  <-- auth challenge --  [ SSO Proxy ]
        |                                   |
        | 401 / redirect to IdP login       | session cookie validated
        |                                   |
        X (agent cannot log in)             v
                                      [ Guard /approve ]
                                            |
                                            v
                                       Approval page rendered
```

An agent that receives the approval URL and tries to fetch it programmatically hits the SSO challenge and cannot
proceed. A human opening the same URL in their browser completes the SSO login (or uses an existing session) and lands
on the Guard approval page normally.

---

## Proxy options

### Cloudflare Access (SaaS)

Zero-code deployment for organizations already using Cloudflare.

1. Add Guard's hostname to your Cloudflare zone.
2. In the Cloudflare Zero Trust dashboard, create an **Application** for Guard's hostname/path.
3. Set the policy to require authentication via your IdP
  (Okta, Azure AD, Google Workspace, etc.).
4. Cloudflare injects a signed `Cf-Access-Jwt-Assertion` header on every
  authenticated request — useful for future audit correlation.

Cloudflare Access passes the authenticated user's email in the
`Cf-Access-Authenticated-User-Email` header. You can use this in Guard's access
logs for audit purposes.

### Pomerium (self-hosted, open source)

Good choice if you need on-premises or air-gapped deployments.

Example `config.yaml` policy entry:

```yaml
routes:
  - from: https://guard.internal.example.com
    to: http://guard:8444
    policy:
      - allow:
          or:
            - domain:
                is: example.com
    pass_identity_headers: true
```

`pass_identity_headers: true` forwards `X-Pomerium-Claim-Email` and related headers to Guard — useful for logging who
approved an escalation.

### nginx + oauth2-proxy (self-hosted)

Compose nginx as the public-facing reverse proxy with oauth2-proxy as a sidecar.

`nginx.conf` snippet:

```nginx
server {
    listen 443 ssl;
    server_name guard.internal.example.com;

    location / {
        auth_request /oauth2/auth;
        error_page 401 = /oauth2/sign_in;

        # Forward identity headers from oauth2-proxy to Guard
        auth_request_set $user $upstream_http_x_auth_request_email;
        proxy_set_header X-Forwarded-User $user;

        proxy_pass http://guard:8444;
    }

    location /oauth2/ {
        proxy_pass http://oauth2-proxy:4180;
    }
}
```

`oauth2-proxy` supports Okta, Azure AD, GitHub, Google, and any OIDC-compliant IdP.

---

## What the SSO proxy should NOT protect

The SSO proxy secures the human-facing approval endpoints (`GET /approve`, `POST /approve`). The Guard
machine-to-machine API endpoints (`/token/unclaimed/list`, `/token/deposit`, `/token/claim`, `/pending`) are protected
separately by the `auth.bearer_token` secret shared between Gate and Guard. Do not route those endpoints through the SSO
proxy — they are not browser-facing and the agent/Gate must be able to reach them directly.

A practical way to enforce this split is to expose two virtual hosts:

| Host | Routes through SSO proxy | Endpoints | Gate config field |
|---|---|---|---|
| `guard.internal.example.com` | Yes | `/approve`, `/healthz`, `/readyz` | `escalation_approval_endpoint` |
| `guard-api.internal.example.com` | No (bearer token only) | `/token/*`, `/pending` | `token_api_endpoint` |

Guard listens on a single address; the proxy layer enforces which paths are human-facing and which are API-facing.

Gate gate config (`gate.yaml`) for the two-hostname split:

```yaml
guard:
  escalation_approval_endpoint: "https://guard.corp.example.com"       # SSO-proxied
  token_api_endpoint:           "https://guard-api.internal.example.com" # direct, bearer-token only
  bearer_token: "envvar://GUARD_BEARER_TOKEN"
```

When `token_api_endpoint` is omitted, Gate falls back to `escalation_approval_endpoint` for all calls — correct for
single-hostname deployments where the SSO proxy exempts the API paths or is not used.

---

## Roadmap: Guard-native OIDC

An SSO proxy is the recommended production approach because it leverages your organization's existing identity
infrastructure with no Guard code changes. Guard-native OIDC authentication (where Guard itself handles the OIDC flow)
is on the roadmap for organizations that cannot deploy an SSO proxy.
