# Static Tool List Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Modify Keep configuration to allow admins to load the tool list for a remote MCP from a static JSON file at startup, bypassing the need for a dynamic tool list request.

**Architecture:** We will extend `BackendConfig` in Keep to include a `tool_list` setting. The file will be read and parsed immediately during Keep's config validation phase, allowing us to fail fast if the file is missing or invalid. The loaded tools will be cached on the configuration struct and served directly by the Router's `ListTools` method.

**Tech Stack:** Go, modelcontextprotocol/go-sdk/mcp, yaml.v3

---

### Task 1: Update Keep Configuration Structures

**Files:**
- Modify: `internal/keep/config.go`
- Modify: `internal/keep/router_test.go`

- [ ] **Step 1: Add new config structs**

Add `ToolListConfig` and update `BackendConfig` in `internal/keep/config.go`:

```go
type ToolListConfig struct {
	Source string `yaml:"source"` // "file" | "remote"
	File   string `yaml:"file"`
}

type BackendConfig struct {
    // ... existing fields ...
	ToolList    ToolListConfig       `yaml:"tool_list"`
	StaticTools []*mcp.Tool          `yaml:"-"` // Loaded directly if Source == "file"
}
```

- [ ] **Step 2: Rename and update validation function**

Rename `validateBackendIdentityConfig` to `validateBackendConfig` to reflect its broader scope, and change it to accept a pointer `*BackendConfig`. 

```go
func validateBackendConfig(cfg *BackendConfig) error {
	// ... existing identity validation ...

	if cfg.ToolList.Source == "file" {
		if cfg.ToolList.File == "" {
			return fmt.Errorf("tool_list.file is required when source is 'file'")
		}
		
		// Path resolution: Use as-is if absolute, otherwise resolve against CWD.
		attemptedPath, err := filepath.Abs(cfg.ToolList.File)
		if err != nil {
			return fmt.Errorf("failed to resolve absolute path for static tool list file: configured=%q: %w", cfg.ToolList.File, err)
		}
		cwd, err := os.Getwd()
		if err != nil {
			return fmt.Errorf("failed to determine current working directory for path resolution: %w", err)
		}

		data, err := os.ReadFile(attemptedPath)
		if err != nil {
			return fmt.Errorf("failed to read static tool list file: configured=%q attempted=%q base_dir=%q (cwd): %w", cfg.ToolList.File, attemptedPath, cwd, err)
		}
		var result mcp.ListToolsResult
		if err := json.Unmarshal(data, &result); err != nil {
			return fmt.Errorf("failed to parse static tool list file: configured=%q attempted=%q: %w", cfg.ToolList.File, attemptedPath, err)
		}
		cfg.StaticTools = result.Tools
	} else if cfg.ToolList.Source != "" && cfg.ToolList.Source != "remote" {
		return fmt.Errorf("tool_list.source %q is invalid; must be 'file' or 'remote'", cfg.ToolList.Source)
	}

	return nil
}
```

- [ ] **Step 3: Update loop in config parsing**

In `internal/keep/config.go` (inside the `if` block parsing backends), update the loop to use a pointer:

```go
	for i := range c.Responsibility.Backends {
		if err := validateBackendConfig(&c.Responsibility.Backends[i]); err != nil {
			return cfgloader.PostureReport{}, fmt.Errorf("mcp_backends[%d] (%q): %w", i, c.Responsibility.Backends[i].Name, err)
		}
	}
```

- [ ] **Step 4: Update existing validation tests in router_test.go**

In `internal/keep/router_test.go`, rename all existing `TestValidateBackendIdentityConfig_*` functions to `TestValidateBackendConfig_*`. Update the function calls inside them from `validateBackendIdentityConfig` to `validateBackendConfig(&cfg)`. Note that since the function now takes a pointer, you will need to pass `&cfg` or update the loop variable to be addressable. Also, update any error formatting strings (e.g. `t.Errorf("validateBackendIdentityConfig(...) = %v", err)`) to use the new `validateBackendConfig` name for consistency.

- [ ] **Step 5: Write tests for static tool list config validation**

In `internal/keep/router_test.go` (alongside the other `validateBackendConfig` tests), add tests to verify file loading:

```go
func TestValidateBackendConfig_StaticToolList(t *testing.T) {
	// Create a temporary JSON file with a mock tool
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "tools.json")
	
	toolsData := `{
		"tools": [
			{
				"name": "static_tool",
				"description": "A tool loaded from a file"
			}
		]
	}`
	err := os.WriteFile(filePath, []byte(toolsData), 0644)
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}

	cfg := BackendConfig{
		ToolList: ToolListConfig{
			Source: "file",
			File:   filePath,
		},
	}

	err = validateBackendConfig(&cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(cfg.StaticTools) != 1 || cfg.StaticTools[0].Name != "static_tool" {
		t.Errorf("failed to load static tools correctly: %+v", cfg.StaticTools)
	}
}

func TestValidateBackendConfig_StaticToolListErrors(t *testing.T) {
	cfgNoFile := BackendConfig{
		ToolList: ToolListConfig{
			Source: "file",
		},
	}
	if err := validateBackendConfig(&cfgNoFile); err == nil {
		t.Error("expected error when source is file but no file is provided")
	}

	cfgInvalidSource := BackendConfig{
		ToolList: ToolListConfig{
			Source: "invalid",
		},
	}
	if err := validateBackendConfig(&cfgInvalidSource); err == nil {
		t.Error("expected error for invalid source")
	}

	cfgMissingFile := BackendConfig{
		ToolList: ToolListConfig{
			Source: "file",
			File:   "missing/relative/path.json",
		},
	}
	err := validateBackendConfig(&cfgMissingFile)
	if err == nil {
		t.Error("expected error for missing file")
	} else {
		errMsg := err.Error()
		if !strings.Contains(errMsg, "attempted=") || !strings.Contains(errMsg, "base_dir=") {
			t.Errorf("error message missing diagnostic info, got: %v", errMsg)
		}
		// Extract attempted path to verify it is absolute
		parts := strings.SplitN(errMsg, "attempted=\"", 2)
		if len(parts) == 2 {
			pathPart := strings.SplitN(parts[1], "\"", 2)[0]
			if !filepath.IsAbs(pathPart) {
				t.Errorf("expected attempted path to be absolute, got: %q", pathPart)
			}
		} else {
			t.Errorf("could not extract attempted path from error: %v", errMsg)
		}
	}

	// Malformed JSON test
	tmpDir := t.TempDir()
	malformedPath := filepath.Join(tmpDir, "malformed.json")
	_ = os.WriteFile(malformedPath, []byte("{ not valid json "), 0644)
	
	cfgMalformedFile := BackendConfig{
		ToolList: ToolListConfig{
			Source: "file",
			File:   malformedPath,
		},
	}
	err = validateBackendConfig(&cfgMalformedFile)
	if err == nil {
		t.Error("expected error for malformed file")
	} else {
		errMsg := err.Error()
		if !strings.Contains(errMsg, "configured=") || !strings.Contains(errMsg, "attempted=") {
			t.Errorf("error message missing diagnostic info, got: %v", errMsg)
		}
	}
}
```

### Task 2: Serve Static Tools from Router

**Files:**
- Modify: `internal/keep/router.go`
- Modify: `internal/keep/router_test.go`

- [ ] **Step 1: Write failing test for static tool routing**

In `internal/keep/router_test.go`:

```go
func TestRouter_ListTools_Static(t *testing.T) {
	mockTool := &mcp.Tool{
		Name:        "static_tool",
		Description: "A static tool",
	}

	cfg := BackendConfig{
		Name: "static_backend",
		ToolList: ToolListConfig{
			Source: "file",
		},
		StaticTools: []*mcp.Tool{mockTool},
	}

	router := NewRouter([]BackendConfig{cfg})
	
	// Should return the static tools without attempting to connect to a real backend
	tools, err := router.ListTools(context.Background(), "static_backend")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(tools) != 1 || tools[0].Name != "static_tool" {
		t.Errorf("expected to get static tool, got: %+v", tools)
	}
}
```

- [ ] **Step 2: Update ListTools to serve static tools**

In `internal/keep/router.go`, modify `ListTools`:

```go
func (r *Router) ListTools(ctx context.Context, serverName string) ([]*mcp.Tool, error) {
	r.mu.Lock()
	conn, ok := r.backends[serverName]
	r.mu.Unlock()

	if !ok {
		return nil, fmt.Errorf("unknown backend %q", serverName)
	}

	// Serve static tools if configured
	conn.cfgMu.RLock()
	source := conn.cfg.ToolList.Source
	staticTools := conn.cfg.StaticTools
	conn.cfgMu.RUnlock()

	if source == "file" {
		return staticTools, nil
	}

	session, err := r.sessionFor(ctx, serverName)
	if err != nil {
		return nil, err
	}
	resp, err := session.ListTools(ctx, &mcp.ListToolsParams{})
	if err != nil {
		return nil, fmt.Errorf("list tools from %q: %w", serverName, err)
	}
	return resp.Tools, nil
}
```

- [ ] **Step 3: Run tests to ensure everything passes**

First, run the specific test:
`go test ./internal/keep -run TestRouter_ListTools_Static`
Expected: PASS

Then, run all tests in the package to ensure the validation refactoring didn't introduce regressions:
`go test ./internal/keep`
Expected: PASS
