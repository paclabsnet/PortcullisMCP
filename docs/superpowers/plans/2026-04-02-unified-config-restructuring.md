# Unified Configuration Restructuring Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Restructure Portcullis-Gate, Portcullis-Keep, and Portcullis-Guard YAML configurations into a unified, symmetrical, and domain-organized model as defined in the [Unified Config Design Doc](../specs/2026-04-02-unified-config-restructuring-design.md).

**Architecture:** This plan implements the **Unified Peer Model** where all three services share identical top-level blocks (`server`, `identity`, `peers`, `responsibility`, `operations`). It standardizes peer-to-peer authentication, server endpoint definitions, and adopts a "Strategy + Config" pattern for extensibility.

**Tech Stack:** Go, YAML, PAC.Labs Config Loader.

---

### Task 1: Shared Core Structures

**Files:**
- Create: `internal/shared/config/unified.go`
- Modify: `internal/shared/types.go`

- [ ] **Step 1: Define Shared Peer Auth structures**
In `internal/shared/config/unified.go`, define the standardized `PeerAuth` and `AuthCredentials` structures.

```go
package config

import "github.com/paclabsnet/PortcullisMCP/internal/shared/tlsutil"

type PeerAuth struct {
	Type        string          `yaml:"type"` // "none", "bearer", "mtls"
	Credentials AuthCredentials `yaml:"credentials"`
}

type AuthCredentials struct {
	BearerToken string `yaml:"bearer_token"`
	Cert        string `yaml:"cert"`
	Key         string `yaml:"key"`
	ServerCA    string `yaml:"server_ca"`
}

type ServerConfig struct {
	Endpoints map[string]EndpointConfig `yaml:"endpoints"`
}

type EndpointConfig struct {
	Listen string            `yaml:"listen"`
	TLS    tlsutil.TLSConfig `yaml:"tls"`
	Auth   PeerAuth          `yaml:"auth"`
}

type IdentityConfig struct {
	Source string                 `yaml:"source"`
	Config map[string]interface{} `yaml:"config"`
}

type OperationsConfig struct {
	Storage   StorageConfig   `yaml:"storage"`
	Telemetry TelemetryConfig `yaml:"telemetry"`
	Logging   LoggingConfig    `yaml:"logging"`
	Limits    LimitsConfig    `yaml:"limits"`
}

type StorageConfig struct {
	Backend string                 `yaml:"backend"`
	Config  map[string]interface{} `yaml:"config"`
}
```

- [ ] **Step 2: Commit**
```bash
git add internal/shared/config/unified.go
git commit -m "feat: add shared unified config structures"
```

---

### Task 2: Restructure Portcullis-Gate

**Files:**
- Modify: `internal/gate/config.go`
- Test: `internal/gate/config_test.go`
- Test: `internal/gate/server_secrets_test.go`

- [ ] **Step 1: Update `Config` and `Responsibility` structs**
Modify `internal/gate/config.go` to match the new unified schema. Ensure `management_api` is now `responsibility.agent_interaction` (or `server.endpoints.management_ui`).

- [ ] **Step 2: Update `SecretAllowlist`**
```go
var SecretAllowlist = []string{
	"peers.keep.auth.credentials.bearer_token",
	"peers.keep.auth.credentials.cert",
	"peers.keep.auth.credentials.key",
	"peers.keep.auth.credentials.server_ca",
	"peers.guard.auth.credentials.bearer_token",
	"server.endpoints.management_ui.auth.credentials.bearer_token",
	"identity.config.client_secret",
}
```

- [ ] **Step 3: Update `Validate` and fix broken references in Gate**
Fix all references to `Config.Keep`, `Config.Guard`, `Config.ManagementAPI`, `Config.Sandbox`, and `Config.ProtectedPaths`.

- [ ] **Step 4: Update tests**
Update `internal/gate/config_test.go` and `internal/gate/server_secrets_test.go` to use the new YAML structure.

- [ ] **Step 5: Run tests and commit**
```bash
go test ./internal/gate/...
git add internal/gate/config.go internal/gate/config_test.go internal/gate/server_secrets_test.go
git commit -m "feat(gate): migrate to unified config structure"
```

---

### Task 3: Restructure Portcullis-Keep

**Files:**
- Modify: `internal/keep/config.go`
- Test: `internal/keep/config_test.go`

- [ ] **Step 1: Update `Config` and `Responsibility` structs**
Modify `internal/keep/config.go` to match the new unified schema.

- [ ] **Step 2: Update `SecretAllowlist`**
```go
var SecretAllowlist = []string{
	"server.endpoints.main.tls.cert",
	"server.endpoints.main.tls.key",
	"server.endpoints.main.tls.client_ca",
	"server.endpoints.main.auth.credentials.bearer_token",
	"responsibility.issuance.signing_key",
}
```

- [ ] **Step 3: Update `Validate` and fix references**
Fix references to `Config.Listen`, `Config.Backends`, `Config.PDP`, etc.

- [ ] **Step 4: Update tests**
Update `internal/keep/config_test.go`.

- [ ] **Step 5: Run tests and commit**
```bash
go test ./internal/keep/...
git add internal/keep/config.go internal/keep/config_test.go
git commit -m "feat(keep): migrate to unified config structure"
```

---

### Task 4: Restructure Portcullis-Guard

**Files:**
- Modify: `internal/guard/config.go`
- Test: `internal/guard/config_test.go`

- [ ] **Step 1: Update `Config` and `Responsibility` structs**
Modify `internal/guard/config.go`. Update `server.endpoints` to include `approval_ui` and `token_api`.

- [ ] **Step 2: Update `SecretAllowlist`**
```go
var SecretAllowlist = []string{
	"server.endpoints.token_api.auth.credentials.bearer_token",
	"responsibility.issuance.signing_key",
	"operations.storage.config.password",
}
```

- [ ] **Step 3: Update `Validate` and fix references**
Fix references to `Config.Listen`, `Config.TokenStore`, etc.

- [ ] **Step 4: Update tests**
Update `internal/guard/config_test.go`.

- [ ] **Step 5: Run tests and commit**
```bash
go test ./internal/guard/...
git add internal/guard/config.go internal/guard/config_test.go
git commit -m "feat(guard): migrate to unified config structure"
```

---

### Task 5: Migrate All Configuration YAMLs

**Files:**
- Modify: `config/gate-config.example.yaml`
- Modify: `config/gate-config.minimal-oidc-file.yaml`
- Modify: `config/gate-config.minimal-oidc-login.yaml`
- Modify: `config/gate-config.minimal.yaml`
- Modify: `config/guard-config.example.yaml`
- Modify: `config/guard-config.minimal.yaml`
- Modify: `config/keep-config.example.yaml`
- Modify: `config/keep-config.minimal-oidc.yaml`
- Modify: `config/keep-config.minimal.yaml`
- Modify: `config/keep-config.mock-workflow.yaml`
- Modify: `deploy/docker-sandbox/gate-demo.yaml`
- Modify: `deploy/docker-sandbox/guard-demo.yaml`
- Modify: `deploy/docker-sandbox/keep-demo.yaml`
- Check: `deploy/docker-sandbox/docker-compose.yml`

- [ ] **Step 1: Update all Gate configurations in config/ and deploy/ to the new format.**
- [ ] **Step 2: Update all Keep configurations in config/ and deploy/ to the new format.**
- [ ] **Step 3: Update all Guard configurations in config/ and deploy/ to the new format.**
- [ ] **Step 4: Verify docker-compose.yml for environment variable or mount consistency.**
- [ ] **Step 5: Commit**
```bash
git add config/ deploy/
git commit -m "docs: update all example and demo configs to unified structure"
```

---
