# Plan: Add log-level command-line flag to all services

Implement a command-line flag `--log-level` for `portcullis-gate`, `portcullis-keep`, and `portcullis-guard`. The flag overrides the setting in the YAML configuration.  Setting the `--log-format` is deferred for a later release 

## Objective
Provide a consistent way to override the logging level at startup for debugging purposes across all Portcullis services.

## Key Files & Context
- `internal/shared/config/unified.go`: Implement the shared `SetupLogging` logic.
- `cmd/portcullis-gate/main.go`: Add flag and call `SetupLogging`.
- `cmd/portcullis-keep/main.go`: Add flag and call `SetupLogging`.
- `cmd/portcullis-guard/main.go`: Add flag and call `SetupLogging`.

## Implementation Steps

### Phase 1: Shared Logging Setup Logic
0.  Set up a bootstrap logger at level INFO for the first few messages that arrive
    before the command line and config YAML are processed
1.  **Modify `internal/shared/config/unified.go`**:
    - Add `SetupLogging(cfg LoggingConfig, mode string, levelOverride string)` function.
    - This function will:
        - Determine the target level (LevelOverride > cfg.Level > Default: INFO).
        - If `mode == ModeProduction` and `levelOverride != ""`:
           - if the override is from the command line, ignore it, and explain why, with a message like:

             "NOTICE: --log-level flag ignored in production mode
  Command-line log level overrides are not permitted in production mode.
  To change log level in production mode, update the configuration file."

        - Parse the level string (DEBUG, INFO, WARN, ERROR).
          - If the level string is invalid, fail immediately with an error message
        - Configure a global `slog` handler (JSON if `cfg.Format == "json"`, 
          otherwise Text).
        - Call `slog.SetDefault()`.

### Phase 2: Update Service Entrypoints
2.  **Update `cmd/portcullis-gate/main.go`**:
    - Add `logLevel := flag.String("log-level", "", "override logging level (debug, info, warn, error)")`.
    - After loading config, call `cfgloader.SetupLogging(cfg.Operations.Logging, cfg.Mode, *logLevel)`.
3.  **Update `cmd/portcullis-keep/main.go`**:
    - Same as Gate.
4.  **Update `cmd/portcullis-guard/main.go`**:
    - Same as Gate.

## Verification & Testing
1.  **Manual Verification**:
    - Run `portcullis-keep -config ... --log-level debug` and verify that debug logs (like `decision logger started`) appear.
    - Run without the flag and verify that the YAML setting is respected.
    - Run with `--log-level debug` in `mode: production` and verify the change is ignored and the warning message (described above) is emitted



## Automated Testing

Add automated tests to verify logging precedence, validation, production-mode behavior, and emitted output filtering.

1. Unit tests for resolution logic
  - Create table-driven tests for a pure resolver that determines: 
    - effective log level
    - level source (default, yaml, cli)
    - production notice behavior
    - validation errors
  - Required cases:
   - no yaml level and no cli level uses default info
   - yaml level only uses yaml value
   - cli level overrides yaml in non-production mode
   - production mode with cli level follows policy (either ignore with notice, or 
     allow with warning)
   - invalid yaml level returns error
   - invalid cli level returns error
   - mixed-case levels normalize correctly (Debug, DEBUG, debug)
2. Unit tests for emitted log filtering
  - Configure logger output to an in-memory buffer.
  - For each effective level:
    - emit debug, info, warn, error messages
    - assert only messages at or above the effective level are present
  - Verify both text and json format paths produce expected output shape.
3. Unit tests for startup notice behavior
  - In production mode:
    - verify notice/warning is emitted when cli override is present (or verify ignore 
      notice, depending on chosen policy)
  - In non-production mode:
    - verify no production-only notice is emitted.
4. Entrypoint wiring tests
  - Add lightweight tests per service command to verify:
    - log-level flag is parsed correctly
    - parsed value is passed into shared logging setup
  - Keep these tests narrow (argument parsing and parameter forwarding only).
5. Optional integration smoke test
  - Run one service binary with:
    - config level info
    - cli level debug
  - Assert startup output indicates effective level and source.
  - Keep this as a small smoke test; do not rely on it for full behavior coverage.

### Acceptance Criteria

1. Precedence is enforced consistently: cli over yaml over default (except production policy exception, if configured).
2. Invalid levels fail fast with clear error text.
3. Production override policy is deterministic and tested.
4. Log output filtering is verified in automated tests.
5. All tests pass in normal go test runs.

