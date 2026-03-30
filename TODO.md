# Implementation Plan

## Task 1: Add preferred_username and acr claims to Principal

**Motivation:** In Azure AD and many enterprise IdPs, `sub` is an opaque per-application
identifier — not the human-readable login name. `preferred_username` carries the UPN
(e.g. `alice@corp.com`) that OPA policy rules are typically written against. `acr`
(Authentication Context Class Reference) gives policies a single signal for authentication
strength (e.g. `"mfa"`), complementing the existing `amr` array.

### Step 1 — `internal/shared/types.go`

Add two fields to `UserIdentity`:

```go
PreferredUsername string `json:"preferred_username,omitempty"`
ACR               string `json:"acr,omitempty"`
```

Add the same two fields to `Principal`:

```go
PreferredUsername string `json:"preferred_username,omitempty"`
ACR               string `json:"acr,omitempty"`
```

### Step 2 — `internal/keep/identity.go`

**`oidcVerifyingNormalizer.Normalize`** (after the existing claim extractions, before
constructing `shared.Principal`):

```go
preferredUsername, _ := claims["preferred_username"].(string)
acr, _               := claims["acr"].(string)
```

Include both in the returned `Principal`.

**`passthroughNormalizer.Normalize`**: pass through `id.PreferredUsername` and `id.ACR`
into the returned `Principal`.

### Step 3 — Rego reference implementation

In `policies/rego/portcullis/tabular/decision.rego`, update the example `principal`
block in the large input-schema comment to document the two new fields:

```
"preferred_username": "alice@corp.com",   # human-readable login name (Azure AD / Okta)
"acr": "mfa",                              # authentication strength signal
```

No Rego logic changes are required — the fields are passed through in `principal` and
policy authors can reference them like any other field (e.g.
`input.authorization_request.principal.acr == "mfa"`).

### Step 4 — Tests (`internal/keep/identity_test.go`)

Add table-driven test cases for:

- `oidcVerifyingNormalizer`: token with `preferred_username` + `acr` claims → both
  appear in the returned `Principal`.
- `oidcVerifyingNormalizer`: token without those claims → fields are empty strings (no
  panic, no error).
- `passthroughNormalizer`: `UserIdentity` with `PreferredUsername` and `ACR` set →
  both appear in `Principal`.

---

## Task 2: Allow multiple sandbox directories in Gate config

**Motivation:** Users with multiple unrelated working trees
(e.g. `~/projects/client-a`, `~/projects/client-b`, `/var/data/exports`) currently
have no clean way to fast-path all of them without opening a broad common ancestor.

The change extends `sandbox.directory` (singular string) to support
`sandbox.directories` (list of strings) while keeping the old key as a
backward-compatible single-entry alias. All listed directories are equally trusted
for fast-path; protected paths continue to take precedence over all of them.
There is intentionally no per-directory policy — keep it simple.

### Step 1 — `internal/gate/config.go`

Change `SandboxConfig`:

```go
type SandboxConfig struct {
    Directory   string   `yaml:"directory"`   // backward-compatible single entry
    Directories []string `yaml:"directories"` // multi-directory list
}
```

Add an `EffectiveDirs() []string` helper that merges both fields (deduplicating),
with `Directory` treated as a first entry if non-empty and not already in the list.
Expand `~` in each path (matching the existing `expandHome` logic in `server.go`).

```go
// EffectiveDirs returns the deduplicated list of configured sandbox directories,
// expanding ~ in each entry. Directory is included as a first entry when set and
// not already present in Directories.
func (c SandboxConfig) EffectiveDirs() []string { ... }
```

### Step 2 — `internal/gate/fastpath.go`

Replace the single-directory Rule 2 with a loop over `g.cfg.Sandbox.EffectiveDirs()`:

```go
// Rule 2: all paths must be within at least one sandbox directory.
for _, dir := range g.cfg.Sandbox.EffectiveDirs() {
    sandbox, err := resolvePath(dir)
    if err != nil {
        continue
    }
    allInSandbox := true
    for _, r := range resolved {
        if !isContainedIn(r, sandbox) {
            allInSandbox = false
            break
        }
    }
    if allInSandbox {
        return FastPathAllow, nil
    }
}
```

A tool call is fast-path-allowed if ALL of its paths fall within a single sandbox
directory (not split across multiple). This preserves the current semantics while
supporting multiple directories.

### Step 3 — `internal/gate/localfs/server.go`

**`fsServer` struct:** add `sandboxDirs []string` alongside the existing `sandbox`
(which becomes the primary directory, used only for resolving relative paths).

```go
type fsServer struct {
    sandbox     string   // primary: relative-path base
    sandboxDirs []string // all configured sandbox dirs (for resolve + list)
}
```

**`NewServer`:** change signature to `NewServer(sandboxDirs []string)`. The first
entry is the primary (for relative-path resolution). Fail if the slice is empty.

**`resolve`:** replace the single-sandbox containment check with a loop over
`s.sandboxDirs`. A path is accepted if it falls within ANY of the configured
sandbox directories.

**`listAllowedDirectories`:** list all entries in `s.sandboxDirs` instead of the
single `s.sandbox`.

**`Connect`:** change signature to `Connect(ctx context.Context, sandboxDirs []string)`.

### Step 4 — `internal/gate/server.go`

Update the call site:

```go
dirs := cfg.Sandbox.EffectiveDirs()
if len(dirs) > 0 {
    expanded := make([]string, len(dirs))
    for i, d := range dirs {
        expanded[i], err = expandHome(d)
        if err != nil { ... }
    }
    localFSSession, err = localfs.Connect(ctx, expanded)
    ...
}
```

### Step 5 — Tests

**`internal/gate/fastpath_test.go`**

Add multi-sandbox cases:
- Path inside sandbox A → `FastPathAllow`
- Path inside sandbox B → `FastPathAllow`
- Path spanning both sandboxes (one path in A, one in B, e.g. a copy_file call) → `FastPathForward` (not all in one sandbox)
- Path outside all sandboxes → `FastPathForward`
- Protected path overrides sandbox B → `FastPathDeny`
- `EffectiveDirs` deduplication: `directory` + `directories` with overlap → no duplicate resolution

**`internal/gate/localfs/server_test.go`**

Update existing tests for new `NewServer([]string)` / `Connect(ctx, []string)` signatures.

Add:
- `resolve` accepts paths in sandbox A or sandbox B.
- `resolve` rejects paths outside all configured directories.
- `listAllowedDirectories` response includes all configured directories.
