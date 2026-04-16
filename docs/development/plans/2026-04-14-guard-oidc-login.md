# Portcullis-Guard OIDC Login Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a secure, server-side OIDC login flow to Portcullis-Guard with opaque session cookies and robust lifecycle management.

**Architecture:** Implement a server-side `AuthStore` for PKCE state and sessions. Use a browser-bound correlation cookie for login security and an opaque UUID session cookie for authentication. Use AES-GCM for cookie encryption with a dedicated `session_secret`.

**Tech Stack:** Go, OIDC (Auth Code + PKCE), AES-GCM, Redis/Memory.

---

### Task 1: Shared OIDC Base Configuration

**Files:**
- Modify: `internal/shared/config/unified.go`

- [ ] **Step 1: Define OIDCBaseConfig structure**

```go
// OIDCBaseConfig defines the fundamental settings for an OIDC provider.
type OIDCBaseConfig struct {
	IssuerURL   string   `yaml:"issuer_url" mapstructure:"issuer_url"`
	Client      struct {
		ID     string `yaml:"id" mapstructure:"id"`
		Secret string `yaml:"secret" mapstructure:"secret"`
	} `yaml:"client" mapstructure:"client"`
	Scopes      []string `yaml:"scopes" mapstructure:"scopes"`
	RedirectURI string   `yaml:"redirect_uri" mapstructure:"redirect_uri"`
}
```

- [ ] **Step 2: Commit**

```bash
git add internal/shared/config/unified.go
git commit -m "feat: add shared OIDCBaseConfig for tree-like configuration"
```

---

### Task 2: Guard Configuration Update

**Files:**
- Modify: `internal/guard/config.go`

- [ ] **Step 1: Define guard-local IdentityConfig and update InterfaceConfig**

Guard defines its own typed `IdentityConfig` (not `cfgloader.IdentityConfig`). Update the `Identity` field in `Config` from `cfgloader.IdentityConfig` to the new guard-local type.

```go
// In internal/guard/config.go

// IdentityConfig is guard-local (replaces cfgloader.IdentityConfig for this component).
type IdentityConfig struct {
	Strategy string `yaml:"strategy"` // "oidc-login" | ""
	Config   struct {
		cfgloader.OIDCBaseConfig `yaml:",inline" mapstructure:",squash"`
		Session                  struct {
			IdleTimeoutMins  int `yaml:"idle_timeout_mins" mapstructure:"idle_timeout_mins"`
			MaxLifetimeHours int `yaml:"max_lifetime_hours" mapstructure:"max_lifetime_hours"`
		} `yaml:"session" mapstructure:"session"`
	} `yaml:"config"`
}

type InterfaceConfig struct {
	Templates          string `yaml:"templates"`
	GateManagementPort int    `yaml:"gate_management_port"`
	SessionSecret      string `yaml:"session_secret"`
}
```

Also update `Config` struct:
```go
// Change:
Identity cfgloader.IdentityConfig `yaml:"identity"`
// To:
Identity IdentityConfig `yaml:"identity"`
```

- [ ] **Step 2: Update validation logic**

- Ensure `session_secret` is required when `identity.strategy` is `"oidc-login"`.
- Ensure required OIDC fields (`issuer_url`, `client.id`, `client.secret`, `redirect_uri`) are present when strategy is `"oidc-login"`.

- [ ] **Step 3: Commit**

```bash
git add internal/guard/config.go
git commit -m "feat: update guard config for OIDC login and session secret"
```

---

### Task 3: Storage Layer Extension (Interfaces)

**Files:**
- Modify: `internal/guard/store.go`

- [ ] **Step 1: Define AuthStore interfaces**

```go
type PKCEState struct {
	State        string    `json:"state"`
	Nonce        string    `json:"nonce"`
	CodeVerifier string    `json:"code_verifier"`
	ReturnPath   string    `json:"return_path"`
	ExpiresAt    time.Time `json:"expires_at"`
}

type AuthSession struct {
	SessionID    string       `json:"session_id"`
	UserID       string       `json:"user_id"`
	DisplayName  string       `json:"display_name"`
	Tokens       OIDCTokenSet `json:"tokens"` // OIDCTokenSet defined in Task 5
	CreatedAt    time.Time    `json:"created_at"`
	LastActiveAt time.Time    `json:"last_active_at"`
}

type AuthStore interface {
	StorePKCE(ctx context.Context, state PKCEState) error
	GetPKCE(ctx context.Context, state string) (*PKCEState, error)
	DeletePKCE(ctx context.Context, state string) error

	StoreSession(ctx context.Context, session AuthSession) error
	GetSession(ctx context.Context, sessionID string) (*AuthSession, error)
	DeleteSession(ctx context.Context, sessionID string) error
	
	UpdateSessionActivity(ctx context.Context, sessionID string) error
}
```

- [ ] **Step 2: Commit**

```bash
git add internal/guard/store.go
git commit -m "feat: define AuthStore interfaces for PKCE and session management"
```

---

### Task 4: In-Memory AuthStore Implementation

**Files:**
- Modify: `internal/guard/memstore.go`

- [ ] **Step 1: Implement StorePKCE, GetPKCE, DeletePKCE**
- [ ] **Step 2: Implement StoreSession, GetSession, DeleteSession**
- [ ] **Step 3: Implement UpdateSessionActivity**
- [ ] **Step 4: Update cleanup worker to purge expired PKCE and Sessions**
- [ ] **Step 5: Commit**

```bash
git add internal/guard/memstore.go
git commit -m "feat: implement in-memory AuthStore"
```

---

### Task 5: OIDC Manager for Guard

**Files:**
- Create: `internal/guard/oidc.go`

- [ ] **Step 1: Port and adapt OIDCLoginManager from Gate**
- [ ] **Step 2: Define OIDCTokenSet (Access, ID, Refresh, Expiry)**
- [ ] **Step 3: Implement StartLogin (returns URL and PKCEState)**
- [ ] **Step 4: Implement HandleCallback (exchanges code, returns ID/tokens)**
- [ ] **Step 5: Implement DoRefresh (synchronous refresh using refresh token)**
- [ ] **Step 6: Commit**

```bash
git add internal/guard/oidc.go
git commit -m "feat: add OIDCManager for Guard"
```

---

### Task 6: Session & Cookie Utilities

**Files:**
- Create: `internal/guard/session.go`

- [ ] **Step 1: Implement AES-GCM encryption/decryption for cookies**

    Key derivation: SHA-256 hash of the `session_secret` string to produce a fixed 32-byte AES-256 key. No other key sizes are supported.
- [ ] **Step 2: Implement cookie set/get helpers (Secure, HttpOnly, SameSite=Lax)**
- [ ] **Step 3: Implement UUID session ID generation**
- [ ] **Step 4: Commit**

```bash
git add internal/guard/session.go
git commit -m "feat: add session and cookie utilities"
```

---

### Task 7: Auth Middleware & Redirect Logic

**Files:**
- Create: `internal/guard/middleware.go`

- [ ] **Step 1: Implement AuthMiddleware**
    - Check `portcullis_session` cookie.
    - Validate against `AuthStore`.
    - Check idle/max TTL policies.
    - Perform on-demand refresh if ID token expired.
    - Redirect to `/auth/login` if unauthenticated. The `/auth/login` handler immediately initiates PKCE + IdP redirect (no interstitial page).
- [ ] **Step 2: Implement return_path validation (Relative + /approve only)**
- [ ] **Step 3: Commit**

```bash
git add internal/guard/middleware.go
git commit -m "feat: add AuthMiddleware and redirect validation"
```

---

### Task 8: Server Integration & Routes

**Files:**
- Modify: `internal/guard/server.go`

- [ ] **Step 1: Initialize OIDCManager and AuthStore in NewServer** — only when `identity.strategy == "oidc-login"`; otherwise these remain nil.
- [ ] **Step 2: Register routes: `GET /auth/login`, `GET /auth/callback`, `POST /auth/logout`** — only when `identity.strategy == "oidc-login"`.
- [ ] **Step 3: Wrap `/approve` handlers with AuthMiddleware** — only when `identity.strategy == "oidc-login"`; when strategy is empty/unset, `/approve` is served without authentication as today.
- [ ] **Step 4: Implement the new route handlers**
    - `GET /auth/login`: immediately generates PKCE state and redirects to IdP (no interstitial page).
    - `GET /auth/callback`: handles IdP callback, exchanges code, creates session, redirects to `return_path`.
    - `POST /auth/logout`: deletes server-side session, clears cookie, redirects to `/approve`.
- [ ] **Step 5: Commit**

```bash
git add internal/guard/server.go
git commit -m "feat: integrate OIDC login routes and middleware into Guard server"
```

---

### Task 9: UI Updates

**Files:**
- Modify: `internal/guard/templates/approval.html`

- [ ] **Step 1: Update approval.html to show "Logged in as [User]"** — only rendered when session data is present in the template context; no change to rendering when OIDC is not configured.
- [ ] **Step 2: Add "Sign Out" POST form button**
- [ ] **Step 3: Commit**

```bash
git add internal/guard/templates/approval.html
git commit -m "feat: update approval UI template for OIDC login status and logout"
```

---

### Task 10: Verification & Tests

**Files:**
- Create: `internal/guard/oidc_test.go`
- Create: `internal/guard/session_test.go`
- Modify: `internal/guard/server_test.go`

- [ ] **Step 1: Unit tests for cookie encryption**
- [ ] **Step 2: Unit tests for session lifecycle (idle/max TTL)**
- [ ] **Step 3: Integration test for full login/redirect flow (mock IdP)**
- [ ] **Step 4: Security test for Open Redirect prevention**
- [ ] **Step 5: Commit**

```bash
git add internal/guard/*_test.go
git commit -m "test: add unit and integration tests for Guard OIDC login"
```
