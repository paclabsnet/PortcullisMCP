# Plan: Fine-grained and Wildcard Filesystem Permissions

This plan outlines the implementation of fine-grained strategy control and wildcard support for the `portcullis-localfs` tool provider in Portcullis-Gate.

## 1. Goal
Provide administrators with more granular control over local filesystem operations by introducing an operation-based and tool-based `strategy` configuration. This strategy will determine whether an operation is automatically allowed, denied, or requires verification from Portcullis-Keep.

## 2. Configuration Schema Changes
Update `internal/gate/config.go` to include the new `strategy` structure within `LocalFSConfig`.

### 2.1. `LocalFSStrategyConfig` Struct
The configuration supports both category-level defaults (Read, Write, Update, Delete) and specific tool-level overrides.

```go
type LocalFSStrategyConfig struct {
	// Category-level keys. These apply to all tools in the category unless
	// overridden by a tool-specific key.
	// 
	// Values: 
	//   - "allow": (Scoped) Automatically allow within workspace; verify otherwise.
	//   - "verify": (Global) Always forward to Keep for authorization.
	//   - "deny": (Global) Always reject immediately.
	Read   string `yaml:"read"`
	Write  string `yaml:"write"`
	Update string `yaml:"update"`
	Delete string `yaml:"delete"`

	// Tool-specific overrides. If set, these take precedence over category keys.
	ReadTextFile           string `yaml:"read_text_file"`
	ReadMediaFile          string `yaml:"read_media_file"`
	ReadMultipleFiles      string `yaml:"read_multiple_files"`
	WriteFile              string `yaml:"write_file"`
	EditFile               string `yaml:"edit_file"`
	CreateDirectory        string `yaml:"create_directory"`
	ListDirectory          string `yaml:"list_directory"`
	ListDirectoryWithSizes string `yaml:"list_directory_with_sizes"`
	DirectoryTree          string `yaml:"directory_tree"`
	MoveFile               string `yaml:"move_file"`
	SearchFiles            string `yaml:"search_files"`
	CopyFile               string `yaml:"copy_file"`
	DeleteFile             string `yaml:"delete_file"`
	SearchWithinFiles      string `yaml:"search_within_files"`
	GetFileInfo            string `yaml:"get_file_info"`
	ListAllowedDirectories string `yaml:"list_allowed_directories"`
}
```

### 2.2. Updated `LocalFSConfig`
```go
type LocalFSConfig struct {
	Enabled   bool                  `yaml:"enabled"`
	Workspace SandboxConfig         `yaml:"workspace"`
	Forbidden ForbiddenConfig       `yaml:"forbidden"`
	Strategy  LocalFSStrategyConfig `yaml:"strategy"`
}
```

### 2.3. Configuration Validation
Update `(c *Config) Validate()` in `internal/gate/config.go` to include:
*   **Value Constraints**: Ensure all defined strategy fields contain only `"allow"`, `"verify"`, or `"deny"`. Validation is case-sensitive and strict to prevent configuration errors.

## 3. Tool Categorization
The following hard-coded mapping will categorize `portcullis-localfs` tools into operations:

| Operation | Tools |
| :--- | :--- |
| **Read** | `read_text_file`, `read_media_file`, `read_multiple_files`, `list_directory`, `list_directory_with_sizes`, `directory_tree`, `search_files`, `search_within_files`, `get_file_info`, `list_allowed_directories` |
| **Write** | `write_file`, `create_directory`, `move_file`, `copy_file` |
| **Update** | `edit_file` |
| **Delete** | `delete_file` |

*Note: `move_file` and `copy_file` are treated as "write" operations.*

## 4. Logic Implementation: `FastPath` Updates
The `FastPath` function in `internal/gate/fastpath.go` will be updated to implement the following execution order and evaluation rules:

### 4.1. Execution Order
1.  **Path Extraction & Resolution**: Extract all path arguments (including `directory` key) and resolve them to absolute, symlink-free paths.
2.  **Forbidden Check**: If any resolved path is within a `forbidden` directory -> **Deny** immediately (`FastPathDeny`).
3.  **Strategy Resolution**:
    *   Identify the tool's category (Read, Write, Update, Delete).
    *   Determine the effective strategy (Priority: Tool Key > Category Key > Default: `allow`).
4.  **Path Evaluation**:
    *   If Strategy is `deny` -> **Deny** (Global Kill Switch).
    *   If Strategy is `verify` -> **Forward** (Global).
    *   If Strategy is `allow` (or default):
        *   If all paths are within `workspace` (or `workspace` contains `*`) -> **Allow** (`FastPathAllow`).
        *   If any path is outside `workspace` -> **Forward** (Implicit `verify`).

### 4.2. Decision Mapping
*   `allow` -> `FastPathAllow` (Execute locally)
*   `deny` -> `FastPathDeny` (Reject immediately)
*   `verify` -> `FastPathForward` (Forward to Keep)

## 5. Robust Path Extraction
*   **Audit and Extend**: `extractPaths` in `internal/gate/fastpath.go` will be updated to handle the `directory` argument key in addition to `path`, `source`, `destination`, and `paths`.
*   **Goal**: Ensures the strategy evaluator identifies path arguments even if the tool call uses the `directory` key (common in some MCP filesystem clients), preventing them from incorrectly bypassing the strategy.

## 6. Wildcard Support
*   The `*` entry in `workspace.directories` will be interpreted as a sentinel for "all paths".
*   **Implementation Detail**: In the `FastPath` sandbox loop, the code will check for the literal `*` string *before* calling `resolvePath(dir)`. If `*` is found, the paths are considered "in sandbox" for that workspace entry.
*   Note: Even with `*` matching all paths, the `forbidden` directory check (Step 2) is still performed first and takes absolute precedence.

## 7. Verification Plan
### 7.1. Unit Tests (`internal/gate/fastpath_test.go`)
*   **TestWildcardWorkspace**: Verify that `workspace: ["*"]` allows any path not in `forbidden`.
*   **TestStrategyPrecedence**: Verify that specific tool overrides take precedence over category defaults.
*   **TestGlobalDenyVerify**: Verify that `deny` and `verify` apply even outside the workspace, while `allow` downgrades to `verify` outside the workspace.
*   **TestForbiddenOverride**: Verify that `forbidden` directories are denied even if `workspace` is `*` and strategy is `allow`.
*   **TestImplicitVerify**: Verify that paths outside `workspace` (when `*` is not used) result in `FastPathForward`.
*   **TestOperationMapping**: Verify that `copy_file` and `move_file` are correctly categorized as "write" operations and governed by the "write" strategy.

### 7.2. Integration Tests
*   Verify that existing integration tests still pass with the default (empty) strategy, ensuring backward compatibility for sandbox operations.

## 8. Cleanup
*   **Remove Dead Code**: Delete the commented-out `isFastPathTool` function and its associated `@TODO: 2026-04-02 : remove` marker in `internal/gate/fastpath.go`.

## 9. Documentation & Clarity
*   **Inline Documentation**: Struct field comments in `internal/gate/config.go` will explicitly state that `deny` and `verify` are global, whereas `allow` is restricted to the defined `workspace`.
*   **Example Configs**: Update example configuration files in `config/` (e.g., `gate-config.example.yaml`) to show usage of the new `strategy` and `*` wildcard features.

## 10. Configuration Examples

### 10.1. Global Restricted Gate
Blocks all deletes and forces verification for all writes, even within the sandbox.
```yaml
portcullis-localfs:
  enabled: true
  workspace:
    directories: ["~/Documents"]
  strategy:
    delete: deny    # Global: blocks all deletes everywhere (Note: deny is always global regardless of workspace)
    write: verify   # Global: all writes require Keep approval
    read: allow     # Scoped: reads in ~/Documents are allowed immediately
```

### 10.2. High-Trust Gate (Internal Tooling)
Allows everything on the machine except sensitive system folders.
```yaml
portcullis-localfs:
  enabled: true
  workspace:
    directories: ["*"] # Wildcard: applies strategy to the whole disk
  forbidden:
    directories: ["~/.ssh", "/etc"]
  strategy:
    read: allow
    write: allow
    update: allow
    delete: verify # Even with *, deletes are guarded by Keep
```
