# Identity Normalization Webhook Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement pluggable identity normalization via an optional enterprise webhook with LRU caching, data minimization, and strict validation.

**Architecture:**
1.  **Normalization Peer**: Configured under `peers.normalization`, provides the webhook endpoint, authentication, and claim filters.
2.  **Identity Strategy**: Standard normalizers (OIDC/HMAC) are extended to optionally delegate to the normalization peer after cryptographic validation.
3.  **Caching & Validation**: LRU cache minimizes latency, while strict limits on Principal fields prevent resource abuse.

**Tech Stack:** Go 1.25.0, `net/http`, standard library (for LRU, a simple doubly-linked list + map).

---

### Task 1: Configuration & Secret Allowlist

**Files:**
- Modify: `internal/shared/config/unified.go`
- Modify: `internal/keep/config.go`
- Modify: `internal/shared/identity/identity.go`
- Test: `internal/keep/config_test.go`

- [ ] **Step 1: Update `internal/shared/config/unified.go`**
Add `NormalizationPeerConfig` to support the new peer type.

```go
// NormalizationPeerConfig holds settings for the identity normalization webhook peer.
type NormalizationPeerConfig struct {
	PeerAuth     `yaml:",inline"`
	AllowClaims  []string `yaml:"allow_claims"`
	DenyClaims   []string `yaml:"deny_claims"`
	Timeout      int      `yaml:"timeout"`        // seconds
	MaxPayloadKB int      `yaml:"max_payload_kb"` // kilobytes
}
```

- [ ] **Step 2: Update `internal/keep/config.go`**
Add `Normalization` to `PeersConfig` and update `SecretAllowlist`.

```go
type PeersConfig struct {
	Guard cfgloader.GuardPeerConfig `yaml:"guard"`
	Normalization cfgloader.NormalizationPeerConfig `yaml:"normalization"`
}

var SecretAllowlist = []string{
	...
	"peers.normalization.auth.credentials.bearer_token",
}
```

- [ ] **Step 3: Update `internal/shared/identity/identity.go`**
Add cache and validation fields to `NormalizerConfig`.

```go
type NormalizerConfig struct {
	...
	CacheTTL           int `yaml:"cache_ttl"`
	CacheMaxEntries    int `yaml:"cache_max_entries"`
	MaxUserIDLength    int `yaml:"max_userid_length"`
	MaxGroupNameLength int `yaml:"max_group_name_length"`
	MaxGroupsCount     int `yaml:"max_groups_count"`
}
```

- [ ] **Step 4: Update `internal/keep/config_test.go`**
Add a test case for the new configuration fields.

- [ ] **Step 5: Commit**
`git add internal/shared/config/unified.go internal/keep/config.go internal/shared/identity/identity.go internal/keep/config_test.go && git commit -m "feat: add normalization webhook configuration types"`

### Task 2: Shared Identity Logic (Filtering & Validation)

**Files:**
- Modify: `internal/shared/identity/identity.go`
- Create: `internal/shared/identity/identity_test.go`

- [ ] **Step 1: Implement `FilterClaims`**
Add a utility to filter a claims map based on allow/deny lists.

```go
func FilterClaims(claims map[string]any, allow []string, deny []string) map[string]any {
	filtered := make(map[string]any)
	for k, v := range claims {
		// If allowlist is provided, only include those
		if len(allow) > 0 {
			allowed := false
			for _, a := range allow {
				if a == k {
					allowed = true
					break
				}
			}
			if !allowed {
				continue
			}
		}
		// If denylist is provided, exclude those
		denied := false
		for _, d := range deny {
			if d == k {
				denied = true
				break
			}
		}
		if denied {
			continue
		}
		filtered[k] = v
	}
	return filtered
}
```

- [ ] **Step 2: Implement `ValidatePrincipal`**
Add a utility to validate a `Principal` against configured limits.

```go
func ValidatePrincipal(p shared.Principal, cfg NormalizerConfig) error {
	if p.UserID == "" {
		return fmt.Errorf("normalized identity missing user_id")
	}
	if cfg.MaxUserIDLength > 0 && len(p.UserID) > cfg.MaxUserIDLength {
		return fmt.Errorf("user_id exceeds maximum length of %d", cfg.MaxUserIDLength)
	}
	if len(p.Groups) > 0 {
		if cfg.MaxGroupsCount > 0 && len(p.Groups) > cfg.MaxGroupsCount {
			return fmt.Errorf("groups count exceeds maximum of %d", cfg.MaxGroupsCount)
		}
		if cfg.MaxGroupNameLength > 0 {
			for _, g := range p.Groups {
				if len(g) > cfg.MaxGroupNameLength {
					return fmt.Errorf("group name %q exceeds maximum length of %d", g, cfg.MaxGroupNameLength)
				}
			}
		}
	}
	return nil
}
```

- [ ] **Step 3: Write tests for filtering and validation**
Create `internal/shared/identity/identity_test.go` and test edge cases (empty lists, oversized strings, etc.).

- [ ] **Step 4: Commit**
`git add internal/shared/identity/identity.go internal/shared/identity/identity_test.go && git commit -m "feat: implement claim filtering and principal validation"`

### Task 3: LRU Cache Implementation

**Files:**
- Create: `internal/keep/cache.go`
- Create: `internal/keep/cache_test.go`

- [ ] **Step 1: Implement `PrincipalCache`**
A thread-safe LRU cache using a doubly-linked list and a map.

```go
type PrincipalCache struct {
	mu         sync.Mutex
	maxEntries int
	cache      map[string]*list.Element
	ll         *list.List
}

type entry struct {
	key       string
	principal shared.Principal
	expiry    time.Time
}

func NewPrincipalCache(maxEntries int) *PrincipalCache {
	return &PrincipalCache{
		maxEntries: maxEntries,
		cache:      make(map[string]*list.Element),
		ll:         list.New(),
	}
}

func (c *PrincipalCache) Get(key string) (shared.Principal, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if ele, hit := c.cache[key]; hit {
		e := ele.Value.(*entry)
		if time.Now().Before(e.expiry) {
			c.ll.MoveToFront(ele)
			return e.principal, true
		}
		c.removeElement(ele)
	}
	return shared.Principal{}, false
}

func (c *PrincipalCache) Add(key string, principal shared.Principal, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if ele, hit := c.cache[key]; hit {
		c.ll.MoveToFront(ele)
		ele.Value.(*entry).principal = principal
		ele.Value.(*entry).expiry = time.Now().Add(ttl)
		return
	}
	ele := c.ll.PushFront(&entry{key, principal, time.Now().Add(ttl)})
	c.cache[key] = ele
	if c.ll.Len() > c.maxEntries {
		c.removeOldest()
	}
}
// ... helper methods ...
```

- [ ] **Step 2: Write tests for `PrincipalCache`**
Verify TTL expiration and LRU eviction when capacity is reached.

- [ ] **Step 3: Commit**
`git add internal/keep/cache.go internal/keep/cache_test.go && git commit -m "feat: implement thread-safe LRU cache for normalized principals"`

### Task 4: Normalization Client

**Files:**
- Create: `internal/keep/identity_webhook.go`
- Create: `internal/keep/identity_webhook_test.go`

- [ ] **Step 1: Implement `NormalizationClient`**
Handles the HTTP POST to the webhook, including authentication, timeout, and payload size enforcement.

```go
type NormalizationClient struct {
	endpoint     string
	token        string
	timeout      time.Duration
	maxPayloadKB int
	httpClient   *http.Client
}

func (c *NormalizationClient) Normalize(ctx context.Context, claims map[string]any) (shared.Principal, error) {
	// 1. JSON Marshal claims
	// 2. Check size < maxPayloadKB
	// 3. POST with Authorization: Bearer <token>
	// 4. Check response size < maxPayloadKB
	// 5. Unmarshal to shared.Principal
}
```

- [ ] **Step 2: Enforce HTTPS in production**
Check `mode == production` and ensure the endpoint uses `https://`.

- [ ] **Step 3: Write tests for `NormalizationClient`**
Use a test HTTP server to verify requests and responses, including authentication headers and error handling.

- [ ] **Step 4: Commit**
`git add internal/keep/identity_webhook.go internal/keep/identity_webhook_test.go && git commit -m "feat: implement normalization webhook client"`

### Task 5: Integration in Normalizers

**Files:**
- Modify: `internal/keep/identity.go`
- Test: `internal/keep/identity_test.go`

- [ ] **Step 1: Add webhook and cache to normalizers**
Update `oidcVerifyingNormalizer` and `hmacVerifyingNormalizer` structs to include `NormalizationClient` and `PrincipalCache`.

- [ ] **Step 2: Wire the logic in `Normalize`**
After verification, if a webhook client is present, use the cache/webhook flow. Use `FilterClaims` and `ValidatePrincipal`.

- [ ] **Step 3: Update `init()` and `buildIdentityNormalizer`**
Update the factory functions to initialize the client and cache if configured.

- [ ] **Step 4: Write integration tests**
Update `internal/keep/identity_test.go` to cover the full flow with the webhook enabled.

- [ ] **Step 5: Commit**
`git add internal/keep/identity.go internal/keep/identity_test.go && git commit -m "feat: integrate webhook and cache into identity normalizers"`
