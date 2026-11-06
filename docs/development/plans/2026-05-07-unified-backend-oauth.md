# Unified Backend OAuth Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement a unified backend authentication system in Keep that supports OAuth 2.1, API Keys, and Identity Exchange, all coordinated via a cluster-safe `CredentialsStore`.

**Architecture:** Use a pluggable `CredentialsStore` interface to manage tokens and PKCE state. Consolidate all backend authentication under the `user_identity` config block with a type discriminator.

**Tech Stack:** Go, Redis (GETDEL support), OAuth 2.1, PKCE.

---

### Task 1: Define CredentialsStore Interface and Types

**Files:**
- Create: `internal/keep/credentials_store.go`

- [ ] **Step 1: Define core types and interface**

```go
package keep

import (
	"context"
	"time"
)

type userToken struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	Expiry       time.Time `json:"expiry"`
}

type pendingAuth struct {
	CodeVerifier  string `json:"code_verifier"`
	BackendName   string `json:"backend_name"`
	UserID        string `json:"user_id"`
	TokenEndpoint string `json:"token_endpoint"`
	ClientID      string `json:"client_id"`
	RedirectURI   string `json:"redirect_uri"`
}

type clientReg struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret,omitempty"`
}

type CredentialsStore interface {
	GetToken(ctx context.Context, backend, userID string) (*userToken, error)
	SetToken(ctx context.Context, backend, userID string, token *userToken) error
	DeleteToken(ctx context.Context, backend, userID string) error
	StorePending(ctx context.Context, nonce string, p *pendingAuth) error
	ConsumePending(ctx context.Context, nonce string) (*pendingAuth, error)
	GetClientReg(ctx context.Context, backend string) (*clientReg, error)
	SetClientReg(ctx context.Context, backend string, reg *clientReg) error
}
```

- [ ] **Step 2: Commit**

```bash
git add internal/keep/credentials_store.go
git commit -m "feat(keep): define CredentialsStore interface and types"
```

---

### Task 2: Implement MemoryCredentialsStore

**Files:**
- Modify: `internal/keep/credentials_store.go`
- Create: `internal/keep/credentials_store_test.go`

- [ ] **Step 1: Write failing tests for memory store**

```go
package keep

import (
	"context"
	"testing"
	"time"
)

func TestMemoryCredentialsStore(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryCredentialsStore()

	// Test Token Ops
	token := &userToken{AccessToken: "abc", Expiry: time.Now().Add(time.Hour)}
	if err := s.SetToken(ctx, "b1", "u1", token); err != nil {
		t.Fatalf("SetToken: %v", err)
	}
	got, err := s.GetToken(ctx, "b1", "u1")
	if err != nil || got.AccessToken != "abc" {
		t.Errorf("GetToken mismatch")
	}

	// Test Pending Ops (Consume deletes)
	p := &pendingAuth{CodeVerifier: "v1"}
	if err := s.StorePending(ctx, "n1", p); err != nil {
		t.Fatalf("StorePending: %v", err)
	}
	gotP, err := s.ConsumePending(ctx, "n1")
	if err != nil || gotP.CodeVerifier != "v1" {
		t.Errorf("ConsumePending mismatch")
	}
	gotP2, _ := s.ConsumePending(ctx, "n1")
	if gotP2 != nil {
		t.Errorf("Expected nil after consume")
	}
}
```

- [ ] **Step 2: Implement MemoryCredentialsStore**

```go
type memoryCredentialsStore struct {
	tokens  map[string]*userToken
	pending map[string]*pendingAuth
	clients map[string]*clientReg
}

func NewMemoryCredentialsStore() CredentialsStore { ... }
// Implement all methods using maps and a RWMutex
```

- [ ] **Step 3: Run tests and commit**

```bash
go test -v ./internal/keep -run TestMemoryCredentialsStore
git add internal/keep/credentials_store.go internal/keep/credentials_store_test.go
git commit -m "feat(keep): implement MemoryCredentialsStore"
```

---

### Task 3: Implement RedisCredentialsStore

**Files:**
- Create: `internal/keep/redis_credentials_store.go`

- [ ] **Step 1: Implement Redis store using GETDEL and EXAT**

```go
type redisCredentialsStore struct {
	client redis.UniversalClient
	prefix string
}

func (s *redisCredentialsStore) ConsumePending(ctx context.Context, nonce string) (*pendingAuth, error) {
    // Use s.client.GetDel(ctx, key) - requires Redis 6.2+
}
```

- [ ] **Step 2: Add integration tests (mock redis if needed)**
- [ ] **Step 3: Commit**

```bash
git add internal/keep/redis_credentials_store.go
git commit -m "feat(keep): implement RedisCredentialsStore"
```

---

### Task 4: Update Backend Configuration Schema

**Files:**
- Modify: `internal/keep/config.go`

- [ ] **Step 1: Update `BackendUserIdentity` to include `type`, `oauth`, and `api_key`**

```go
type BackendUserIdentity struct {
	Type      string                   `yaml:"type"` // none, exchange, api_key, oauth
	Placement BackendIdentityPlacement `yaml:"placement"`
	Exchange  BackendIdentityExchange  `yaml:"exchange"`
	OAuth     BackendOAuth             `yaml:"oauth"`
	APIKey    BackendAPIKey            `yaml:"api_key"`
}

type BackendOAuth struct {
	ClientID           string        `yaml:"client_id"`
	CallbackURL        string        `yaml:"callback_url"`
	Scopes             []string      `yaml:"scopes"`
	RefreshWindow      time.Duration `yaml:"refresh_window"`
	FlowTimeout        time.Duration `yaml:"flow_timeout"`
	StoreRefreshTokens bool          `yaml:"store_refresh_tokens"`
}

type BackendAPIKey struct {
	Source string `yaml:"source"`
}
```

- [ ] **Step 2: Implement strict startup validation**

```go
func (c *BackendUserIdentity) Validate(mode string) error {
    // Check type-specific blocks
    // Check HTTPS for callback_url in production
    // Check duration strings
}
```

- [ ] **Step 3: Commit**

```bash
git commit -am "feat(keep): update backend config schema with unified identity types"
```

---

### Task 5: Implement OAuth Callback Handler

**Files:**
- Modify: `internal/keep/server.go`

- [ ] **Step 1: Add callback route and handler**

```go
mux.HandleFunc("GET /oauth/callback", s.handleOAuthCallback)
```

- [ ] **Step 2: Implement `handleOAuthCallback` logic**
- Extract state, call `ConsumePending`.
- Perform exchange using `golang.org/x/oauth2`.
- Store token in `CredentialsStore`.
- [ ] **Step 3: Add unit tests for handler**
- [ ] **Step 4: Commit**

```bash
git commit -am "feat(keep): implement OAuth callback handler"
```

---

### Task 6: Implement Flow Initiation in Router

**Files:**
- Modify: `internal/keep/router.go`

- [ ] **Step 1: Add `tryStartOAuthFlow` to Router**
- Fetch PRM/ASM.
- Store pending flow state.
- Construct and return auth URL in `CallToolResult`.
- [ ] **Step 2: Update `CallTool` to capture 401s and trigger flow**
- [ ] **Step 3: Commit**

```bash
git commit -am "feat(keep): implement OAuth flow initiation in Router"
```

---

### Task 7: Update Token Injection logic

**Files:**
- Modify: `internal/keep/router.go` (RoundTripper)

- [ ] **Step 1: Update `headerInjectingRoundTripper`**
- Check `user_identity.type`.
- If `oauth`, fetch from `CredentialsStore`.
- Handle background refresh if needed.
- If `api_key`, use the resolved secret.
- [ ] **Step 2: Add operational warning for memory storage**

```go
if storeStrategy == "memory" && hasOAuthBackends {
    slog.Warn("backend OAuth state is process-local; restarts and failover will lose pending auth flows and tokens.")
}
```

- [ ] **Step 3: Commit**

```bash
git commit -am "feat(keep): update token injection to support all identity types"
```

---

### Task 8: End-to-End Integration Test

**Files:**
- Create: `internal/keep/oauth_integration_test.go`

- [ ] **Step 1: Mock MCP server with OAuth challenges**
- [ ] **Step 2: Verify full flow (401 -> Click URL -> Callback -> Injected Call)**
- [ ] **Step 3: Commit**

```bash
go test -v ./internal/keep -run TestOAuthIntegration
git add internal/keep/oauth_integration_test.go
git commit -m "test(keep): add e2e integration test for backend OAuth"
```
