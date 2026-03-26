# Phase 2

## Tasks


### Task: Improve API
- We need to version Keep's API with Gate, or version the Wrapped MCP Request, or both, so we know what to expect in the contents
- We need to version the logging API (how Gate sends logs to Keep)
- priority: high , but only after we've gotten all of the core communications done, no need in versioning our API too early



### Task: Add Secret Management to Gate
Gate doesn't currently perform the YAML secret resolution that is done by Keep and Guard.

Whether or not we include support for vault-style secrets, we can and should use the same
mechanism for environment variables and files

Guidelines:
  - Gate should run in degraded mode, which is already a defined failure mode for Gate. It does not stop running, because that
    would make it impossible for the user to determine what the problem is, it would just appear that Portcullis wasn't responding
    without any feedback. It is better for Gate to remain operational and return error messages to the user and Agent when the
    agent tries to use the MCPs

priority: high







### Task: Input sanitizing at Keep and Guard
- standard good hygiene
- priority: medium



### Task: add http for gate, so it can support multiple agents in parallel
i.e. instead of running as a stdio MCP, it can run as an autonomous local process.
- Portcullis-Gate needs to be concurrency-safe
- priority: medium-low





### Task: Routing model for Workflows
when the PDP generates a 'workflow' response, the important information should be
sent to the appropriate workflow system to allow for authorization. But it is quite possible
that in a large organization, different workflow systems will be used to authorize
different types of requests - for example, by MCP, or even perhaps by Tool.

We need to modify the Keep config to allow different workflow plugins to be invoked
for different service / tool combos 

- priority: low





### Task: Acquire Human Credentials (at Gate)
- [x] Token file (Option B) — Gate reads `identity.oidc.token_file`; fails hard (no OS fallback) when source is "oidc" and token is missing or invalid; `~` is now expanded correctly on read
- [ ] Keychain storage — optional future enhancement
- [ ] Device authorization grant (RFC 8628) — fallback for when no token file exists; deferred until need confirmed (see Implementation Details below)
- priority: low



### Task: Optionally Include the traceid in the Deny, Escalate and Workflow messages back to the user
- purpose: allows a user to escalate to the enterprise security team if they aren't allowed to do something they think they should be able to
- low priority



### Task: Optionally create a Gate API to collect the list of DENY responses, along with trace/session information
- not sure if this is necessary. It might be helpful for troubleshooting
- very low priority



## Security Review


1. High: Guard token-claim surface is capability-based and can be open depending on config
- Claim endpoint intentionally unauthenticated: server.go:139
- Guard can run with no bearer token protection for token APIs: server.go:385
- Unclaimed-list response includes raw token material: server.go:414
  
Why this is major:
- Security posture depends heavily on deployment hardening.
- In permissive deployments, token retrieval paths expose high-value artifacts.

Suggested direction:
- Require auth by default for token APIs, return only metadata from list endpoints, and keep raw token retrieval tightly scoped/authenticated.









# Phase 3 / Future

### Task: Support Cloud Vaults (Phase 3)
    These require importing heavy cloud-provider SDKs (AWS/GCP/Azure) and setting up complex test environments. By deferring them, we
    keep the PR surgical and the binary size lean for the first release.

    1. awssec://: AWS Secrets Manager.
    2. gcpsec://: GCP Secret Manager.
    3. azkv://: Azure Key Vault.

    - priority: low




### Task: Pluggable Logging and Redaction
- **Problem**: Enterprises need flexible logging destinations (SIEMs, files, console) and must ensure that sensitive PII or secrets in tool arguments are never leaked to those logs.
- **Fix**: Implement a `LogSink` interface and a "Fail-Safe" redaction engine.
- **Fail-Safe Redaction Definition**: If the redaction engine encounters an error (recursion limit, malformed data), it must replace the entire payload with an error message rather than logging raw data.
- **Implementation scope**:
  - `internal/keep/logsink.go` — Define the `LogSink` interface (`Write`, `Close`).
  - `internal/keep/redaction.go` — Implement the redaction engine with support for:
    - **Global Deny-List**: Keys like `password`, `token`, `secret` are always redacted.
    - **Tool-Specific Rules**: Specific arguments for specific tools (e.g., `email` in `update_user`).
    - **Strict Mode**: An optional "safe-by-default" mode where only explicitly allowed keys are logged.
  - `internal/keep/decisionlog.go` — Refactor to support multiple sinks and apply redaction before sending.
  - **New Sinks**: Implement `ConsoleSink`, `FileSink`, and refactor the existing `WebhookSink`.
  - priority: medium


## Implementation notes


  




