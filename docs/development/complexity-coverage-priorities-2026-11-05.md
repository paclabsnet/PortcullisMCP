# Complexity and Test Coverage Priorities

**Measured:** 2026-11-05  
**Scope:** Go packages under `internal/`  
**Method:** Cyclomatic complexity from `gocyclo`; statement coverage from `go test ./... -coverprofile`.

The test suite measured **67.8% overall statement coverage**. The following production functions combine high cyclomatic complexity with comparatively low coverage and are recommended candidates for focused test additions.

| Priority | Function | Complexity | Coverage | Why it stands out |
|---|---|---:|---:|---|
| 1 | `(*Router).CallTool` in [`internal/keep/router.go`](../../internal/keep/router.go) | 42 | 33.9% | Highest complexity/low coverage overlap among the production functions measured. This path routes tool calls and contains substantial branching. |
| 2 | `(*OIDCLoginManager).refreshLoop` in [`internal/gate/oidclogin.go`](../../internal/gate/oidclogin.go) | 16 | 19.6% | Low coverage of lifecycle and concurrency behavior makes missed cases particularly plausible. |
| 3 | `(*Server).handleCall` in [`internal/keep/server.go`](../../internal/keep/server.go) | 25 | 42.9% | Core authorization, escalation, backend execution, and response path with many branches. |
| 4 | `(*oidcVerifyingNormalizer).Normalize` in [`internal/keep/identity.go`](../../internal/keep/identity.go) | 40 | 60.9% | High complexity and material uncovered behavior in identity validation. |
| 5 | `(*hmacVerifyingNormalizer).Normalize` in [`internal/keep/identity.go`](../../internal/keep/identity.go) | 42 | 78.4% | Very complex; coverage is better, but remaining branches may warrant targeted tests after the lower-coverage candidates. |

Other functions worth reviewing after the first group:

| Function | Complexity | Coverage |
|---|---:|---:|
| `(*Gate).handleToolCall` in [`internal/gate/server.go`](../../internal/gate/server.go) | 26 | 69.2% |
| `identityFromJWT` in [`internal/gate/identity.go`](../../internal/gate/identity.go) | 23 | 75.6% |

## Interpretation

Use complexity and uncovered fraction to prioritize investigation, then inspect uncovered branches before writing tests. A high complexity score alone is not a requirement to test every theoretical path.

This is a prioritization snapshot, not a full audit. Complexity output also includes test functions; those were excluded from the candidate list. Package-level coverage can hide uncovered functions, and tests run in another package do not necessarily contribute coverage to the package containing a shared helper. Re-run the measurements before using these figures to assess future changes.
