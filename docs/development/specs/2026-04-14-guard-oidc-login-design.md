# Spec: Portcullis-Guard OIDC Login

**Status:** Draft
**Date:** 2026-04-14
**Topic:** Adding OIDC-Login support to Portcullis-Guard for interactive approvals.

## 1. Overview
Portcullis-Guard provides a UI for human-in-the-loop approvals. This spec defines the addition of an interactive OIDC login flow to Portcullis-Guard, allowing organizations to require authentication before an approval can be granted.

This implementation follows the **"Minimum Necessary"** principle for client-side state: the browser cookie will contain only an **encrypted or signed minimal session ID**. All sensitive data, including OIDC login/session state and the full token sets, will be stored server-side using Guard's existing storage abstraction (Memory or Redis).

## 2. Goals
- Add OIDC Auth Code + PKCE login flow to Portcullis-Guard.
- Secure the `/approve` UI routes with OIDC authentication when enabled.
- Use a **minimal session ID** in the browser cookie for maximum security.
- Prevent Login CSRF and Session Mixup by binding the login flow to the initiating browser.
- **Prevent Open Redirects** by strictly validating the `return_path`.
- Store OIDC tokens (including Refresh Tokens) and user metadata in a **server-side session store**.
- Implement a clear **Session Lifecycle & TTL Policy** for inactivity and maximum lifetime.
- **Cryptographic Isolation**: Use a dedicated **`session_secret`** for cookie encryption, separate from the escalation token signing key.
- **Modernize Configuration**: Use a nested, tree-like YAML structure for OIDC settings, based on a new **shared OIDC base** in `internal/shared/config`.

## 3. Architecture

### 3.1 Components
- **`OIDCBaseConfig` (New)**: A shared configuration structure in `internal/shared/config` for common OIDC fields (`issuer_url`, `client`, `scopes`, `redirect_uri`).
- **`OIDCManager`**: Handles discovery, PKCE generation, and token exchange.
- **`AuthStore`**: A unified server-side store (extending Guard's existing storage logic) for:
    - **PKCE State**: Short-lived (5-10m) record of `state`, `nonce`, `verifier`, and `return_path`.
    - **Authenticated Sessions**: Opaque session records containing `UserID`, `DisplayName`, and the full `OIDCTokenSet`.
- **`AuthMiddleware`**: Intercepts requests, validates the session ID against the `AuthStore`, and handles redirects/refreshes.

### 3.2 Data Flow (Secure Login Flow)
1. **Initial Access**: User visits `/approve?token=...`.
2. **Middleware Check**: `AuthMiddleware` looks for the `portcullis_session` cookie.
3. **Login Start**: If missing, Guard generates PKCE parameters and a `state` ID.
4. **State Storage**: Guard saves the PKCE parameters and the current request path (`return_path`) in the `AuthStore`, keyed by `state`.
    - **Safety Rule**: The `return_path` **MUST** be a same-origin relative path (e.g., starting with `/`) and **SHOULD** be restricted to an allowlist (e.g., `/approve`).
5. **Browser Binding (Login Cookie)**: Guard sets a short-lived (10m), `HttpOnly`, `Secure`, `SameSite=Lax` cookie named `portcullis_login_state` containing the `state` ID.
6. **Redirection**: User is redirected to the IdP with the `state` ID.
7. **OIDC Flow**: User authenticates with the IdP.
8. **Callback**: IdP redirects back to `/auth/callback?state=...&code=...`.
9. **Correlation Check**: Guard **MUST** verify that the `state` parameter in the URL matches the value in the `portcullis_login_state` cookie.
10. **State Recovery**: Guard retrieves PKCE state from the `AuthStore` using the `state` ID.
11. **Token Exchange**: Guard exchanges the `code` for tokens, validates the `nonce`.
12. **Session Setup**: 
    - Guard creates a new **opaque Session ID** (UUID).
    - Guard stores the full `OIDCTokenSet` and user info in the `AuthStore` keyed by the Session ID.
    - Guard clears the `portcullis_login_state` cookie.
    - Guard redirects to the validated `return_path`.

## 4. Configuration
Guard's `identity` configuration will use a nested, tree-like structure, extending a shared OIDC base:

```yaml
identity:
  strategy: "oidc-login"
  config:
    issuer_url: "https://auth.example.com"
    client:
      id: "portcullis-guard-client"
      secret: "vault://guard/oidc_client_secret"
    scopes: ["openid", "profile", "email", "groups"]
    session:
      idle_timeout_mins: 30
      max_lifetime_hours: 24
    redirect_uri: "https://guard.internal.example.com/auth/callback"

responsibility:
  interface:
    # Dedicated secret for browser session cookie encryption (AES-GCM)
    session_secret: "vault://guard/session_secret"
```

## 5. Implementation Details

### 5.1 Storage (AuthStore)
- **PKCE State**: Keyed by OIDC `state`. Contains `nonce`, `code_verifier`, `return_path`. TTL: 5-10m.
- **Sessions**: Keyed by opaque `session_id`. Contains `UserID`, `DisplayName`, and the **OIDCTokenSet (stored server-side)**.
- **Backend**: Reuses Guard's `Storage` abstraction (Memory for single-instance, Redis for clustered).

### 5.2 Session Lifecycle & TTL Policy
To balance security and usability, the session lifetime is governed by three factors:
- **Sliding Inactivity Timeout**: Every valid request to Guard (where the cookie matches an active session) extends the session's server-side TTL by `session.idle_timeout_mins` (default: 30m).
- **Absolute Maximum Lifetime**: The session is terminated after `session.max_lifetime_hours` (default: 24h) regardless of activity, requiring re-authentication.
- **On-Demand Refresh**: 
    - If the ID token is expired but the session is active (within idle/max limits), Guard attempts a synchronous refresh using the server-side Refresh Token.
    - If refresh succeeds, the session record is updated with new tokens and the inactivity timer is reset.
    - If refresh fails (e.g., token revoked or `invalid_grant`), the session is deleted immediately, and the user is redirected to the login page.

### 5.3 Redirect Validation (Open Redirect Protection)
- When capturing the `return_path`, Guard **MUST** ensure it is a relative path (starts with `/` and not `//`).
- Guard **SHOULD** only allow `return_path` values that match known UI routes (e.g., `/approve`).
- Any invalid or absolute `return_path` **MUST** be rejected and defaulted to `/approve`.

### 5.4 Cookies
- **`portcullis_login_state`**: Short-lived (10m) correlation cookie containing the OIDC `state`. Signed/encrypted.
- **`portcullis_session`**: Long-lived session cookie containing an opaque UUID only. Signed/encrypted.
- **Security**: All cookies must be `HttpOnly`, `Secure`, `SameSite=Lax`.
- **Encryption**: AES-GCM using the **`responsibility.interface.session_secret`**.

### 5.5 Logout
- **Endpoint**: `POST /auth/logout`.
- **Method**: The logout endpoint **MUST** require a `POST` request.
- **Protection**: We rely on `SameSite=Lax` cookie security for basic protection. Full CSRF tokens are not required for this internal tool.
- **Action**: On valid logout, Guard deletes the server-side session from the `AuthStore` and clears the `portcullis_session` cookie.

### 5.6 UI Changes
- Display "Logged in as [DisplayName]" on the approval page.
- Add a "Sign Out" button (form-based `POST`) to the approval page.

## 6. Portcullis-Gate Alignment (Future Task)
To ensure long-term consistency, a follow-up task will be added to modernize `portcullis-gate`'s configuration to use the same shared OIDC base and tree-like structure.

## 7. Testing Strategy
- **Unit Tests**:
    - `AuthStore` session lifecycle and TTL extensions.
    - `return_path` validation logic.
- **Integration Tests**:
    - Complete flow with IdP.
    - **Security Test**: Verify that providing an absolute URL as a `return_path` results in a redirect to the default `/approve` page.
    - **Session Test**: Verify that a session expires after the idle timeout.
    - **Logout Test**: Verify that `POST /auth/logout` correctly terminates the session.
    - Verify that tokens never leak into cookies or the UI.
