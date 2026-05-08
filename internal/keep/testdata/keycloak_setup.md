# Keycloak Setup Guide for DCR End-to-End Testing

This guide describes how to configure a local Keycloak instance to test RFC 7591
Dynamic Client Registration (DCR) with Portcullis Keep.

## Prerequisites

- Docker or a running Keycloak 22+ instance
- A realm for testing (referred to as `test-realm` below)

---

## 1. Start Keycloak

```bash
docker run -d --name keycloak \
  -p 8080:8080 \
  -e KEYCLOAK_ADMIN=admin \
  -e KEYCLOAK_ADMIN_PASSWORD=admin \
  quay.io/keycloak/keycloak:latest start-dev
```

Wait for Keycloak to be ready, then open `http://localhost:8080/admin`.

---

## 2. Create a Test Realm

1. Log in as `admin` / `admin`.
2. Click **Keycloak** (top-left dropdown) > **Create Realm**.
3. Set **Realm name** to `test-realm` and click **Create**.

---

## 3. Enable Dynamic Client Registration

Keycloak requires explicit policy configuration to allow DCR.

### 3.1 Open Client Registration Policies

1. Navigate to **Realm Settings** (left sidebar) > **Client Registration** tab.
2. You will see two policy sections: **Anonymous Access Policies** and **Authenticated Access Policies**.

### 3.2 Configure an Authenticated Access Policy (recommended)

For testing with an Initial Access Token (IAT), use **Authenticated Access**:

1. Under **Authenticated Access Policies**, click the existing **Allowed Client Scopes** or **Trusted Hosts** policy, or add a new one.
2. Ensure the policy allows the `redirect_uris`, `grant_types`, and `response_types` you intend to register.
3. Leave other defaults; the minimal configuration allows `redirect_uri`, `client_name`, `grant_types`, `response_types`, `scope`.

---

## 4. Generate an Initial Access Token (IAT)

1. In the **Client Registration** tab, click **Initial Access Token**.
2. Click **Create**.
3. Set the **Expiration** (e.g. `600` seconds) and **Count** (number of registrations allowed, e.g. `5`).
4. Copy the displayed token — it is shown only once.

This token is passed as `dcr.initial_access_token` in your `keep.yaml`.

---

## 5. Discovery Endpoint

Keycloak exposes the RFC 8414 Authorization Server Metadata (ASM) document at:

```
http://localhost:8080/realms/test-realm/.well-known/openid-configuration
```

The `registration_endpoint` field in this document will be:

```
http://localhost:8080/realms/test-realm/clients-registrations/openid-connect
```

You can either set `dcr.registration_endpoint` explicitly in `keep.yaml` or let
Keep discover it via RFC 8414 discovery.

---

## 6. Keep Configuration for DCR Testing

Add the following to a backend entry in `keep.yaml`:

```yaml
mcp_backends:
  - name: my-backend
    type: http
    url: http://my-backend.internal/mcp
    user_identity:
      type: oauth
      oauth:
        callback_url: http://localhost:8444/oauth/callback
        scopes:
          - openid
          - profile
        store_refresh_tokens: true
        dcr:
          enabled: true
          registration_endpoint: http://localhost:8080/realms/test-realm/clients-registrations/openid-connect
          initial_access_token: ${KEYCLOAK_IAT}
          client_name: "Portcullis Keep (test)"
          timeout: 10s
          failure_cache_ttl: 5m
```

Set the environment variable:

```bash
export KEYCLOAK_IAT="<paste-the-iat-here>"
```

---

## 7. Software Statement Testing (Optional)

If the Keycloak realm enforces a **Software Statement** policy:

1. Navigate to **Client Registration** > **Authenticated Access Policies** > add a policy of type **Software Statement**.
2. Generate a signed JWT (RS256) with the required claims and set it as `dcr.software_statement` in `keep.yaml`.

---

## 8. Verifying the Flow

1. Start Keep: `portcullis-keep -config keep.yaml`
2. Trigger a tool call that requires OAuth authentication.
3. Keep should:
   a. Detect there is no client registration.
   b. POST to the `registration_endpoint` with the IAT.
   c. Receive and store a `client_id` and `client_secret`.
   d. Build the authorization URL using the dynamic `client_id`.
   e. On subsequent calls, reuse the cached registration without re-registering.
4. Check Keep logs for: `keep: dynamic client registration succeeded`.

---

## 9. Troubleshooting

| Symptom | Likely Cause |
|---|---|
| `DCR previously failed: 401 Unauthorized` | IAT is missing, expired, or already used. Generate a new one. |
| `ErrDCRNotSupported` | Keycloak DCR endpoint path is wrong. Check the discovery document. |
| `invalid_client_metadata` | A required field (`redirect_uris`, `grant_types`) is missing. |
| Negative cache not clearing | Use `DEL portcullis:keep:creds:dcr_fail:my-backend` in Redis, or restart Keep (memory store). |
