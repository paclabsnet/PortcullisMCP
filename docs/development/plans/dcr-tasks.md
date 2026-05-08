# Dynamic Client Registration (DCR) Tasks Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement RFC 7591 Dynamic Client Registration in the `keep` service to allow just-in-time registration with IdPs.

**Architecture:** Update `keep` configuration and credentials store to handle dynamic client metadata. Implement a DCR client to communicate with IdPs and integrate it into the OAuth flow with concurrency control (distributed locking and singleflight).

**Tech Stack:** Go, Redis (for distributed state), RFC 7591.

---

### Task 1: Configuration Updates

**Files:**
- Modify: `internal/keep/config.go`

- [ ] **Step 1: Define BackendDCR struct and update BackendOAuth**

```go
// BackendDCR configures RFC 7591 Dynamic Client Registration for a backend.
type BackendDCR struct {
	Enabled              bool          `yaml:"enabled"`
	RegistrationEndpoint string        `yaml:"registration_endpoint"`
	InitialAccessToken   string        `yaml:"initial_access_token"`
	SoftwareStatement    string        `yaml:"software_statement"`
	ClientName           string        `yaml:"client_name"`
	Timeout              time.Duration `yaml:"timeout"`
	FailureCacheTTL      time.Duration `yaml:"failure_cache_ttl"`
}

type BackendOAuth struct {
	// ... existing fields ...
	DCR BackendDCR `yaml:"dcr"`
}
```

- [ ] **Step 2: Add failing test for configuration parsing**
Verify that the new DCR fields are correctly unmarshaled from YAML.

- [ ] **Step 3: Run test to verify it fails**

- [ ] **Step 4: Update config.go implementation**

- [ ] **Step 5: Run test to verify it passes**

- [ ] **Step 6: Commit**

```bash
git add internal/keep/config.go internal/keep/config_test.go
git commit -m "feat(keep): add DCR configuration structures"
```

---

### Task 2: Credentials Store Interface Updates

**Files:**
- Modify: `internal/keep/credentials_store.go`

- [ ] **Step 1: Update clientReg struct**

```go
type clientReg struct {
	ClientID                string `json:"client_id"`
	ClientSecret            string `json:"client_secret,omitempty"`
	ClientSecretExpiresAt   int64  `json:"client_secret_expires_at,omitempty"`
	TokenEndpointAuthMethod string `json:"token_endpoint_auth_method,omitempty"`
	Scopes                  string `json:"scope,omitempty"`
}
```

- [ ] **Step 2: Update CredentialsStore interface**

```go
type CredentialsStore interface {
	// ... existing methods ...
	GetClientReg(ctx context.Context, backend string) (*clientReg, error)
	SetClientRegNX(ctx context.Context, backend string, reg *clientReg) (bool, error)
	LockDCR(ctx context.Context, backend string) (func(), error)
	GetDCRFailure(ctx context.Context, backend string) (string, error)
	SetDCRFailure(ctx context.Context, backend string, reason string, ttl time.Duration) error
}
```

- [ ] **Step 3: Commit**

```bash
git add internal/keep/credentials_store.go
git commit -m "refactor(keep): update CredentialsStore interface for DCR"
```

---

### Task 3: Memory Credentials Store Implementation

**Files:**
- Modify: `internal/keep/credentials_store.go` (or wherever the memory implementation resides)

- [ ] **Step 1: Update memoryStore struct with new fields**
Add `dcrFailures` map and necessary mutexes.

- [ ] **Step 2: Implement new CredentialsStore methods for memoryStore**
Implement `GetClientReg`, `SetClientRegNX`, `LockDCR`, `GetDCRFailure`, and `SetDCRFailure`.

- [ ] **Step 3: Write tests for memoryStore DCR methods**

- [ ] **Step 4: Run tests and verify they pass**

- [ ] **Step 5: Commit**

---

### Task 4: Redis Credentials Store Implementation

**Files:**
- Modify: `internal/keep/redis_credentials_store.go`

- [ ] **Step 1: Implement new CredentialsStore methods for redisStore**
Use Redis commands like `SET ... NX`, `SET ... EX` for locking and failure caching.

- [ ] **Step 2: Write tests for redisStore DCR methods**

- [ ] **Step 3: Run tests and verify they pass**

- [ ] **Step 4: Commit**

---

### Task 5: Implement DCR Client

**Files:**
- Create: `internal/keep/dcr.go`
- Test: `internal/keep/dcr_test.go`

- [ ] **Step 1: Implement RegisterDynamicClient**
Follow RFC 7591 specs for the POST request and response parsing.

- [ ] **Step 2: Write unit tests with mock IdP server**

- [ ] **Step 3: Run tests and verify they pass**

- [ ] **Step 4: Commit**

---

### Task 6: JIT Discovery and Integration

**Files:**
- Modify: `internal/keep/router.go`
- Modify: `internal/keep/server.go`

- [ ] **Step 1: Update resolveOAuthEndpoints to validate registration_endpoint**

- [ ] **Step 2: Implement DCRManager with singleflight**

- [ ] **Step 3: Integrate DCR logic into tryStartOAuthFlow**
Handle JIT registration, locking, and negative caching.

- [ ] **Step 4: Update token exchange and refresh to use dynamic credentials**

- [ ] **Step 5: Write integration tests for the full DCR flow**

- [ ] **Step 6: Commit**

---

### Task 7: Final Verification and Documentation

- [ ] **Step 1: Add Keycloak setup guide for DCR testing**
Create `internal/keep/testdata/keycloak_setup.md`.

- [ ] **Step 2: Run all tests (unit, integration)**

- [ ] **Step 3: Commit**
