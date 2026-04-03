# Plan: Enterprise Hardening — Full Security Posture Assessment & Auth Standardization

Upgrade Portcullis to meet enterprise "Compliance Attestation" standards by implementing a generic reflection-based configuration walker with precise source tracking and standardizing machine-to-machine authentication.

## Objective
1.  **Generic Configuration Walker & Precise Source Tracking**: Refactor the reflection logic from `secrets/resolver.go` into a generic `config.Walk` utility. Implement a dual-decode mechanism in `config.Load` to distinguish between values present in the YAML (`static`), resolved via secrets (`vault`, `env`, `file`), or defaulted by code (`default`).
2.  **Refactor Loadable Interface & Contract**: Update the shared `config.Load` and `Loadable` interface to explicitly return a `PostureReport`. This ensures the security posture is captured and available for logging regardless of whether validation passes.
3.  **High-Signal Security Posture**: Use the generic walker and `SourceMap` to automatically traverse the *entire* resolved configuration struct at startup. Log only "leaf" properties (scalars) while skipping internal/derived fields (`yaml:"-"`) and unexported fields.
4.  **Decommission Unplanned Admin API**: Remove the `/admin/reload` endpoint and associated `responsibility.admin` configuration from Portcullis-Keep, as it was not part of the intended implementation.
5.  **Standardized Authentication (Hygiene)**: Ensure all remaining machine-to-machine APIs strictly use `Authorization: Bearer <token>` or mTLS.

## Key Files & Context
- `internal/shared/config/walker.go`: (New) Generic reflection-based configuration walker (Visitor pattern).
- `internal/shared/config/loader.go`: Update `Load` to perform dual-decode and build `PresenceMap`.
- `internal/shared/secrets/resolver.go`: Refactor to expose scalar `Resolve` function; remove internal walking logic.
- `internal/shared/config/posture.go`: (New) Posture report builder using `config.Walk` and the `SourceMap`.
- `internal/shared/config/unified.go`: Define `PostureReport`, `PostureFinding`, and `SourceMap` types.

## Implementation Steps

### Phase 1: Walker & Precise Source Tracking Refactor
1.  **Create `internal/shared/config/walker.go`**:
    - Implement `Walk(v reflect.Value, path string, visitor func(path string, v reflect.Value) error) error`.
    - **Noise Reduction**: Skip unexported fields and fields with `yaml:"-"` tag.
    - Provide `WalkMap(m map[string]any, path string, visitor func(path string, val any) error) error` to support walking the raw YAML-decoded map.
    - **Canonical Path Requirement**: Both `Walk` and `WalkMap` MUST use the exact same dotted-path format (e.g., `server.endpoints.main.tls.cert`). `Walk` must use YAML tag names; `WalkMap` must use map keys. This is critical for matching struct fields back to their YAML source.
2.  **Define Structures in `internal/shared/config/unified.go`**:
    - `SourceMap map[string]string`
    - `PostureFinding`: `{ Property, Value, Source, Status, Recommendation }`.
    - `PostureReport`: `{ Findings []PostureFinding }`.
3.  **Refactor `internal/shared/config/loader.go`**:
    - Implement `capturePresence(data []byte) map[string]bool`: Unmarshals YAML into `map[string]any` and uses `WalkMap` to build a set of dotted paths actually present in the file.
    - Update `Load[T Loadable]`:
        - 1. Decode struct `T`.
        - 2. Call `capturePresence` to get `PresenceMap`.
        - 3. Use `Walk` on the struct to resolve secrets and build `SourceMap`:
            - If value is secret URI -> `Source = URI.Scheme`.
            - Else if path in `PresenceMap` -> `Source = "static"`.
            - Else -> `Source = "default"`.
    - Update interface: `type Loadable interface { Validate(sources SourceMap) (PostureReport, error) }`.
    - Return `(T, PostureReport, error)`.
4.  **Refactor `internal/shared/secrets/resolver.go`**:
    - Remove `ResolveConfig` and `walkValue`.
    - Expose `Resolve(ctx, raw, path, allowset) (string, error)` for use by `config.Load`.
5.  **Phase 1 Unit Testing (Mandatory)**:
    - `walker_test.go`: Test walking structs and maps.
    - `loader_test.go`: Verify "static" vs "default" vs "vault" attribution for nested fields.

### Phase 2: Posture Infrastructure
6.  **Create `internal/shared/config/posture.go`**:
    - Implement `BuildPostureReport(cfg any, sources SourceMap, allowlist []string) PostureReport`.
    - **High-Signal Visitor**: Only record findings for "leaf" nodes (String, Int, Bool, Float).
    - **Redaction**: Automatically redact any path present in the `allowlist`.
7.  **Implement Logging in `internal/shared/config/unified.go`**:
    - Add `Log()` method to `PostureReport` for structured SIEM-ready logging.

### Phase 3: Service-Specific Auditing & Cleanup
8.  **Update `Config.Validate(sources SourceMap) (PostureReport, error)` in each service**:
    - Update signature to match new `Loadable` interface.
    - Initialize report via `BuildPostureReport(c, sources, SecretAllowlist)`.
9.  **Cleanup Keep Admin API**:
    - Remove `handleReload` and `adminAuthMiddleware` from `internal/keep/server.go`.
    - Remove `AdminConfig` from `internal/keep/config.go`.
    - Delete `internal/keep/server_admin_test.go`.

### Phase 4: Startup Integration
10. **Update `main.go` for all services**:
    - Capture `report` from `LoadConfig` and call `report.Log()`.

## Verification & Testing
1.  **Source Precision**: Verify "static" vs "default" attribution (e.g., `mode` field when missing from YAML).
2.  **Noise Check**: Verify `yaml:"-"` and unexported fields are skipped.
3.  **Exhaustive Logging**: Verify all struct fields with yaml tags (excluding `yaml:"-"`) are logged.
4.  **Redaction Security**: Confirm secrets are logged as `[REDACTED]`.
5.  **Cleanup Verification**: Confirm `/admin/reload` is removed from Keep.
