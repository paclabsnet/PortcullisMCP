# PortcullisMCP Development Guide

This guide contains the coding standards, conventions, and instructions for developers (and AI assistants) working on
PortcullisMCP. For the system architecture and component details, see [ARCHITECTURE.md](./ARCHITECTURE.md).

## Build & Test

- **Build all:** `make build` (or `go build ./cmd/...`)
- **Test all:** `go test ./...`
- **Lint:** `golangci-lint run`

## Key Conventions

- **Project Layout:** Standard Go project layout (`cmd/`, `internal/`).
- **Dependency Injection:** No global state; configuration and dependencies are injected at startup.
- **Interfaces:** Define interfaces in the package that *consumes* them, not the package that implements them.
- **Context:** Always propagate `context.Context` through every function performing I/O.
- **Error Handling:** Return errors instead of panicking. Use sentinel errors defined in `internal/shared/types.go`
  (e.g., `ErrDenied`, `ErrEscalationPending`) for known failure modes.
- **Configuration:** Use YAML files for configuration. Environment variables should only be used for secrets referenced
  within the YAML (using `${VAR}` syntax).
- **Testing Style:** Use table-driven tests with `t.Run`. Integration tests should be tagged with `//go:build
  integration`.
- **Identity:** Always prioritize OIDC tokens over OS identity.
- **Escalation:** The JTI from the pending escalation request MUST be used as the JTI for the issued escalation token to
  allow correlation at the Gate.

## AI Assistant Instructions

- **Research First:** Use `grep_search` and `glob` to understand existing patterns before suggesting changes.
- **Surgical Edits:** Favor `replace` over `write_file` for large existing files to minimize context usage.
- **Verify:** Always run `go test` after making changes to ensure no regressions.
- **Security:** Never hardcode secrets. If a test needs a secret, use a mock or a placeholder.
- **Documentation:** If you add a new interface or significant component, update `ARCHITECTURE.md` accordingly.
- **PR Readiness:** When asked to prepare a PR, ensure `TODO.md` is updated and all local tests pass.
