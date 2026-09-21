# Duplicate-MCP Mode Implementation Plan

> **For agentic workers:** Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Allow `portcullis-gate` to operate correctly when two instances are launched simultaneously by different MCP clients (e.g. Claude Desktop and Claude Code / Cursor), both of which attempt to bind the management UI port (default 7777) for the OIDC callback listener.

**Background:** When two MCP clients are configured to launch portcullis-gate as a stdio server, both instances start and attempt to bind the management UI port. Only one succeeds (the "primary"). The other (the "secondary") is typically the instance the user is actively working with, but it cannot receive the OIDC callback because it doesn't own the port. This is a known Anthropic product issue with no upstream fix timeline.

**Approach:** Introduce an optional `duplicate_mcp_hack: true` flag in the gate config. When enabled, the two instances coordinate via two short-lived files on disk:

1. **PKCE session file** (`~/.portcullis/oidc-pkce-session.json`) — written by the secondary when it starts a login. Contains the `state`, `code_verifier`, and `nonce` needed to complete the PKCE exchange. Mode `0600`. Deleted immediately after state is matched in `HandleCallback`, regardless of whether the token exchange succeeds.

2. **Token file** (`~/.portcullis/oidc-login.token`) — written by `OIDCLoginManager` (primary only) after a successful token exchange or refresh. Contains the raw JWT. Mode `0600`. Deleted or truncated by the primary when the session expires. Persists otherwise across the session.

3. **Flow:**
   - Secondary instance fails to bind the management port → non-fatal, continues in secondary mode.
   - User triggers login from the secondary. Secondary calls `StartLogin`, generates PKCE session, writes it to the PKCE session file, and returns the auth URL (redirect_uri still points to `localhost:7777`).
   - User completes login in browser. IdP redirects to `localhost:7777` — received by the primary.
   - Primary's `HandleCallback` receives a `state` it doesn't recognise in its own session map. In duplicate-mcp mode, instead of erroring, it reads the PKCE session file, finds the matching `state`, deletes the PKCE session file immediately, and completes the token exchange using the stored `code_verifier` and `nonce`.
   - Primary writes the resulting JWT to the token file via `writeTokenFile`, serves a "you may close this window" response to the browser.
   - Secondary is polling the token file. It reads the JWT, calls `SetToken` on its `IdentityCache`, advances its `StateMachine` to `StateAuthenticated`, and continues normally.
   - When the primary's refresh token expires or refresh fails, it deletes the token file. The secondary's poller detects the missing file and calls `Clear()` + `SetUnauthenticated()`.

**Security note:** Writing PKCE session parameters and the OIDC token to disk expands the local attack surface. Both files MUST use mode `0600`. The PKCE session file is deleted immediately after state is matched. This mode is explicitly a workaround for a host-side defect and should be documented as such. Users not affected by the double-launch problem should leave `duplicate_mcp_hack: false`.

**What happens if the primary also needs to log in?** If the primary receives a callback with a `state` it recognises in its own session map, it processes the flow normally (existing behaviour) and also writes the token file so the secondary picks it up.

---

### Task 1: Configuration Schema

**Files:**
- Modify: `internal/gate/config.go`
- Modify: `internal/gate/config_test.go`

- [ ] **Step 1: Add `DuplicateMCPHack` field to top-level `Config`**
  Add `DuplicateMCPHack bool \`yaml:"duplicate_mcp_hack"\`` to the `Config` struct.

- [ ] **Step 2: Add file path fields to `OIDCLoginConfig`**
  Add to `OIDCLoginConfig`:
  ```go
  TokenCacheFile  string `yaml:"token_cache_file"  mapstructure:"token_cache_file"`
  PKCESessionFile string `yaml:"pkce_session_file" mapstructure:"pkce_session_file"`
  ```
  Both `yaml` and `mapstructure` tags are required for correct decoding from the raw config map.
  In `IdentityConfig.Validate()`, when `strategy == "oidc-login"` and `DuplicateMCPHack == true`, default empty fields to:
  - `TokenCacheFile`: `~/.portcullis/oidc-login.token`
  - `PKCESessionFile`: `~/.portcullis/oidc-pkce-session.json`

- [ ] **Step 3: Validate `duplicate_mcp_hack` constraints**
  In `Config.Validate()`:
  - Return an error if `DuplicateMCPHack == true` and `Identity.Strategy != "oidc-login"`.
  - Return an error if `DuplicateMCPHack == true` in multi-tenant mode (inside `validateMultiTenant`).

- [ ] **Step 4: Update config tests**
  Add table-driven cases covering the new validation rules.

---

### Task 2: PKCE Session File (Secondary writes, Primary reads)

**Files:**
- Modify: `internal/gate/oidclogin.go`

- [ ] **Step 1: Define `pkceSessionRecord` struct**
  A JSON-serialisable struct:
  ```go
  type pkceSessionRecord struct {
      State        string    `json:"state"`
      CodeVerifier string    `json:"code_verifier"`
      Nonce        string    `json:"nonce"`
      ExpiresAt    time.Time `json:"expires_at"`
  }
  ```

- [ ] **Step 2: Add `pkceSessionFile` and `tokenCacheFile` fields to `OIDCLoginManager`**
  Add both fields to the struct. Populate them from config in `NewOIDCLoginManager`. Update all call sites.

- [ ] **Step 3: Write PKCE session file in `StartLogin`**
  After releasing `m.mu`, if `m.pkceSessionFile != ""`, serialise the session to JSON and write it (mode `0600`, creating parent dirs with `0700` if needed). On success log at `Debug`: `"duplicate-mcp: wrote PKCE session file"`. Log a warning on failure — do not abort the login.

- [ ] **Step 4: Read PKCE session file in `HandleCallback` for unknown state**
  In `HandleCallback`, after the in-memory session lookup fails (`!ok`), if `m.pkceSessionFile != ""`:
  1. Release `m.mu` before doing any disk I/O (lock only to fetch/delete in-memory state).
  2. Read and parse the PKCE session file.
  3. If the file's `state` matches `queryState` and is not expired, **delete the PKCE session file immediately** (before attempting the token exchange) and log at `Info`: `"duplicate-mcp: completing token exchange using PKCE session file"`.
  4. Use the file's `codeVerifier` and `nonce` to complete the exchange.
  5. If the file does not exist, the state does not match, or the session is expired, fall through to the existing "unknown or expired state" error.

- [ ] **Step 5: Implement `writeTokenFile(idToken string)` helper**
  A private method on `OIDCLoginManager`. Expands the path, creates parent dirs (`0700`), writes the JWT with a trailing newline (mode `0600`). Logs a warning on failure.

- [ ] **Step 6: Call `writeTokenFile` in `HandleCallback` and `refreshLoop`**
  After a successful token exchange in `HandleCallback`, call `m.writeTokenFile(tokens.IDToken)`.
  After a successful refresh in `refreshLoop`, call `m.writeTokenFile(newTokens.IDToken)` and log at `Debug`: `"duplicate-mcp: token file updated after refresh"`.

- [ ] **Step 7: Delete token file on session expiry**
  In `refreshLoop`, when the session transitions to unauthenticated (natural `invalid_grant` expiry) or when refresh fails, delete `m.tokenCacheFile` if it is set and log at `Info`: `"duplicate-mcp: token file deleted; secondary instance will return to unauthenticated state"`. Log a warning on delete failure.

---

### Task 3: Token File Writer — remove from `IdentityCache`

**Files:**
- Modify: `internal/gate/identity.go`

- [ ] **Step 1: Ensure `IdentityCache.SetToken` does NOT write to disk**
  `IdentityCache` must remain a pure memory-only cache updater. It must not write the token file under `oidc-login` strategy. Token file writing is owned entirely by `OIDCLoginManager` (Task 2 above). Verify no file-writing code was inadvertently added here.

---

### Task 4: Token File Poller (Secondary Instance)

**Files:**
- Create: `internal/gate/token_file_poller.go`
- Create: `internal/gate/token_file_poller_test.go`

- [ ] **Step 1: Implement `TokenFilePoller`**
  Struct with:
  - `path string` — expanded absolute path to the token file
  - `interval time.Duration` — poll interval (default 5s)
  - `onToken func(rawJWT string)` — callback invoked when content changes; called with `""` when file disappears or is empty after previously having content

- [ ] **Step 2: Implement `Start(ctx context.Context)`**
  Goroutine that ticks at `interval`. Track a `lastSeen string` and a `hadContent bool`. On each tick:
  1. `os.ReadFile(path)`. If the file does not exist or is empty:
     - If `hadContent == true`, call `onToken("")` and set `hadContent = false`, `lastSeen = ""`.
     - Otherwise skip.
  2. If the file has content and differs from `lastSeen`, call `onToken(strings.TrimSpace(content))`, update `lastSeen`, set `hadContent = true`.
  Stop when `ctx` is cancelled.

- [ ] **Step 3: Unit tests**
  Test:
  - File does not exist initially, then appears — `onToken` called with JWT.
  - File content changes — `onToken` called again with new JWT.
  - File content unchanged — `onToken` not called a second time.
  - File disappears after having content — `onToken` called with `""`.
  - File is empty after having content — `onToken` called with `""`.
  - Context cancellation stops the poller.

---

### Task 5: Wire Duplicate-MCP Mode into Gate Startup

**Files:**
- Modify: `internal/gate/server.go`

- [ ] **Step 1: Add `isSecondary bool` field to `Gate` struct**
  This field is set to `true` when the gate boots into secondary mode. Used to avoid re-checking config conditions across multiple methods.

- [ ] **Step 2: Make management port bind failure non-fatal when `duplicate_mcp_hack` is true**
  In `Gate.Run`, where `mgmt.Start(ctx)` is called, check `g.cfg.DuplicateMCPHack`:
  - If true and `Start` returns an error: set `g.isSecondary = true` and emit `slog.Warn`: `"gate: running in duplicate-mcp secondary mode — management UI disabled; will authenticate via token file written by primary instance"`.
  - If false and `Start` returns an error: before returning the fatal error, emit `slog.Info`: `"gate: failed to bind management port — on Windows, Claude Desktop launches two copies of each MCP server; if this is the cause, set duplicate_mcp_hack: true in gate.yaml to enable coordination between instances"`. Then return the error as before.

- [ ] **Step 3: Start `TokenFilePoller` in secondary mode**
  If `g.isSecondary`, construct and start a `TokenFilePoller` whose `onToken` callback:
  - If `rawJWT != ""`: call `g.identity.SetToken(rawJWT)`; on success call `g.stateMachine.SetAuthenticated()`. Log at `Info`: `"duplicate-mcp: picked up OIDC token from token file; gate is now authenticated"`.
  - If `rawJWT == ""`: call `g.identity.Clear()`; call `g.stateMachine.SetUnauthenticated()`. Log at `Warn`: `"duplicate-mcp: token file removed; gate returning to unauthenticated state"`.

---

### Task 6: Update Example Configs and Docs

**Files:**
- Modify: `config/gate-config.example.yaml`
- Modify: `config/gate-config.minimal-oidc-login.yaml`
- Create: `docs/guides/duplicate-mcp-mode.md`

- [ ] **Step 1: Add `duplicate_mcp_hack` to example config**
  Add a commented-out `duplicate_mcp_hack: false` with a short explanation.

- [ ] **Step 2: Add file path fields to oidc-login example config**
  Add commented-out `token_cache_file` and `pkce_session_file` entries under `identity.config`.

- [ ] **Step 3: Write `docs/guides/duplicate-mcp-mode.md`**
  Explain the problem, the two-file coordination mechanism, how to enable the mode, and the security implications. Include a clear note that this mode exists solely to work around a host-side defect and should not be enabled otherwise.

---

### Task 7: Verification

- [ ] **Step 1: All existing tests pass**
  `go test ./...`

- [ ] **Step 2: Manual smoke test**
  Launch two gate instances with `duplicate_mcp_hack: true`. Trigger login from the secondary. Verify the secondary picks up the token within ~5 seconds and can execute tool calls successfully.
