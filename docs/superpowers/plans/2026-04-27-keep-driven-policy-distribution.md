# Keep-Driven Policy Distribution Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Enable Portcullis-Gate to dynamically fetch its tool configurations (specifically `portcullis-localfs`) from Portcullis-Keep, which in turn fetches them from an OPA PDP.

**Architecture:** Keep exposes a new `GET /config/{resource}` endpoint. Gate calls this at startup and periodically (TTL-based) to refresh its local filesystem policy. Gate implements a fail-closed model with atomic, thread-safe updates and schema validation.

**Tech Stack:** Go, OPA (PDP), HTTP/JSON, sync.RWMutex for concurrency.

---

### Task 1: Update Keep Configuration

**Files:**
- Modify: `internal/keep/config.go`

- [ ] **Step 1: Add `GateStaticPolicy` to `ResponsibilityConfig`**

```go
// Add this new struct
type GateStaticPolicyConfig struct {
	PolicyConfig `yaml:",inline" mapstructure:",inline"`
	Allowlist    []string `yaml:"allowlist" mapstructure:"allowlist"`
}

// Update ResponsibilityConfig
type ResponsibilityConfig struct {
	Policy           PolicyConfig           `yaml:"policy"`
	GateStaticPolicy GateStaticPolicyConfig `yaml:"gate_static_policy"` // Add this
	Backends         []BackendConfig        `yaml:"mcp_backends"`
	Issuance         IssuanceConfig         `yaml:"issuance"`
	Workflow         EscalationConfig       `yaml:"workflow"`
}
```

- [ ] **Step 2: Update `Config.Validate` to include the new policy**

```go
// In internal/keep/config.go: Validate()
	if err := c.Responsibility.Policy.Validate(); err != nil {
		return cfgloader.PostureReport{}, err
	}
	if err := c.Responsibility.GateStaticPolicy.Validate(); err != nil { // Add this
		return cfgloader.PostureReport{}, err
	}
```

- [ ] **Step 3: Run tests to verify config loading**

Run: `go test ./internal/keep/...`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add internal/keep/config.go
git commit -m "keep: add gate_static_policy to configuration"
```

---

### Task 2: Extend Keep PDP for Config Fetching

**Files:**
- Modify: `internal/keep/pdp.go`

- [ ] **Step 1: Add `GetStaticPolicy` to `PolicyDecisionPoint` interface**

```go
type PolicyDecisionPoint interface {
	Evaluate(ctx context.Context, req AuthorizedRequest) (shared.PDPResponse, error)
	GetStaticPolicy(ctx context.Context, resource string) (json.RawMessage, error) // Add this
}
```

- [ ] **Step 2: Implement `GetStaticPolicy` for `noopPDP`**

```go
func (n *noopPDP) GetStaticPolicy(_ context.Context, _ string) (json.RawMessage, error) {
	return json.RawMessage("{}"), nil
}
```

- [ ] **Step 3: Implement `GetStaticPolicy` for `opaClient`**

```go
func (c *opaClient) GetStaticPolicy(ctx context.Context, resource string) (json.RawMessage, error) {
	input := map[string]any{
		"input": map[string]string{
			"resource": resource,
		},
	}
	body, _ := json.Marshal(input)
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("pdp returned status %d", resp.StatusCode)
	}

	var opaResp struct {
		Result struct {
			Policy json.RawMessage `json:"policy"`
		} `json:"result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&opaResp); err != nil {
		return nil, err
	}
	return opaResp.Result.Policy, nil
}
```

- [ ] **Step 4: Commit**

```bash
git add internal/keep/pdp.go
git commit -m "keep: implement GetConfig in PDP"
```

---

### Task 3: Implement Keep `/config` Endpoint

**Files:**
- Modify: `internal/keep/server.go`

- [ ] **Step 1: Add `gateStaticPDP` to `Server` struct**

```go
type Server struct {
	cfg           *Config
	pdp           PolicyDecisionPoint
	gateStaticPDP PolicyDecisionPoint // Add this
    // ...
}
```

- [ ] **Step 2: Initialize `gateStaticPDP` in `New()`**

```go
// In New()
	staticCfg := cfg.Responsibility.GateStaticPolicy
	var gateStaticPDP PolicyDecisionPoint
	switch staticCfg.Strategy {
	case "noop":
		gateStaticPDP = NewNoopPDPClient()
	case "opa", "":
		gateStaticPDP = NewOPAClient(staticCfg.OPA.Endpoint)
	default:
		return nil, fmt.Errorf("unknown static pdp strategy %q", staticCfg.Strategy)
	}

    // ... return &Server{ ..., gateStaticPDP: gateStaticPDP }
```

- [ ] **Step 3: Implement `handleGetConfig` and register route**

```go
// In Run()
	mux.HandleFunc("GET /config/{resource}", s.handleGetConfig)

// Implementation
func (s *Server) handleGetConfig(w http.ResponseWriter, r *http.Request) {
	resource := r.PathValue("resource")
	
	// Allowlist check
	allowed := false
	for _, a := range s.cfg.Responsibility.GateStaticPolicy.Allowlist {
		if a == resource {
			allowed = true
			break
		}
	}
	if !allowed {
		slog.Warn("unauthorized config request", "resource", resource)
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	config, err := s.gateStaticPDP.GetConfig(r.Context(), resource)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(config)
}
```

- [ ] **Step 4: Commit**

```bash
git add internal/keep/server.go
git commit -m "keep: add /config/{resource} endpoint"
```

---

### Task 4: Update Gate Configuration

**Files:**
- Modify: `internal/gate/config.go`

- [ ] **Step 1: Define `LocalFSRulesConfig` and update `LocalFSConfig`**

```go
type LocalFSRulesConfig struct {
	Source         string `yaml:"source"`           // "local" (default) | "keep"
	TTL            int    `yaml:"ttl"`               // seconds
	OnFetchFailure string `yaml:"on_fetch_failure"`  // "cached" (default) | "fail"
}

type LocalFSConfig struct {
	Enabled   bool                  `yaml:"enabled"`
	Rules     LocalFSRulesConfig    `yaml:"rules"`    // Add this
	Workspace SandboxConfig         `yaml:"workspace"`
	Forbidden ForbiddenConfig       `yaml:"forbidden"`
	Strategy  LocalFSStrategyConfig `yaml:"strategy"`
}
```

- [ ] **Step 2: Set defaults in `LocalFSConfig`**

```go
func (c *LocalFSConfig) ApplyDefaults() {
    if c.Rules.Source == "" {
        c.Rules.Source = "local"
    }
    if c.Rules.TTL == 0 {
        c.Rules.TTL = 3600
    }
    if c.Rules.OnFetchFailure == "" {
        c.Rules.OnFetchFailure = "cached"
    }
}
```

- [ ] **Step 3: Commit**

```bash
git add internal/gate/config.go
git commit -m "gate: update LocalFSConfig for keep-driven rules"
```

---

### Task 5: Extend Gate Forwarder

**Files:**
- Modify: `internal/gate/forwarder.go`

- [ ] **Step 1: Add `GetConfig` to `KeepForwarder` interface and implementation**

```go
type KeepForwarder interface {
    // ...
	GetStaticPolicy(ctx context.Context, resource string) (json.RawMessage, error)
}

func (f *httpForwarder) GetStaticPolicy(ctx context.Context, resource string) (json.RawMessage, error) {
	url := fmt.Sprintf("%s/config/%s", f.endpoint, resource)
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	// Add auth headers using f.auth
    
	resp, err := f.client.Do(req)
    // ... handle response and return json.RawMessage
}
```

- [ ] **Step 2: Commit**

```bash
git add internal/gate/forwarder.go
git commit -m "gate: implement GetConfig in KeepForwarder"
```

---

### Task 6: Implement Dynamic Policy Update in LocalFS

**Files:**
- Modify: `internal/gate/localfs/server.go`

- [ ] **Step 1: Add `sync.RWMutex` to `Server` and update tool calls to use it**

```go
type Server struct {
	mu        sync.RWMutex
	workspace SandboxConfig
	forbidden ForbiddenConfig
	strategy  LocalFSStrategyConfig
    // ...
}

// In every tool handler (Read, Write, etc.)
s.mu.RLock()
defer s.mu.RUnlock()
```

- [ ] **Step 2: Implement `UpdatePolicy`**

```go
func (s *Server) UpdatePolicy(w Workspace, f Forbidden, st Strategy) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.workspace = w
	s.forbidden = f
	s.strategy = st
}
```

- [ ] **Step 3: Commit**

```bash
git add internal/gate/localfs/server.go
git commit -m "gate/localfs: add thread-safe UpdatePolicy"
```

---

### Task 7: Implement Gate Refresh Loop

**Files:**
- Modify: `internal/gate/server.go`

- [ ] **Step 1: Implement `refreshLocalFSPolicy`**
- [ ] **Step 2: Implement background goroutine in `New()` or `Run()`**
- [ ] **Step 3: Handle Fail-Closed logic (Deny all if no policy)**

```go
func (g *Gate) startLocalFSPolicyRefresh(ctx context.Context) {
    ticker := time.NewTicker(time.Duration(g.cfg.Tools.LocalFS.Rules.TTL) * time.Second)
    for {
        select {
        case <-ctx.Done():
            return
        case <-ticker.C:
            g.fetchAndApplyLocalFSPolicy(ctx)
        }
    }
}
```

- [ ] **Step 4: Commit**

```bash
git add internal/gate/server.go
git commit -m "gate: implement background policy refresh loop"
```
