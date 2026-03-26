# Phase 2

## Tasks


### Task: Improve API
- We need to version Keep's API with Gate, or version the Wrapped MCP Request, or both, so we know what to expect in the contents
- We need to version the logging API (how Gate sends logs to Keep)
- priority: high , but only after we've gotten all of the core communications done, no need in versioning our API too early






### Task: Input sanitizing at Keep and Guard [DONE]
- standard good hygiene
- priority: medium
- Completed in v0.2.11: LimitsConfig added to Keep and Guard configs; body size limits,
  field length caps, log batch validation, and decision-field enum validation implemented.
  Guard token-claim surface hardened: auth required by default, AllowUnauthenticatedTokenAPIs
  flag added, expires_at returned in unclaimed list, remote_addr logged on claim.



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


1. [RESOLVED v0.2.11] Guard token-claim surface is capability-based and can be open depending on config
- Auth is now required by default for token APIs; deployers must explicitly set
  auth.allow_unauthenticated_token_apis: true to opt out (development/sandbox only).
- Guard fails fast at startup if no bearer token is configured and the flag is not set.
- expires_at is now included in the unclaimed-list response.
- remote_addr is now logged on every token claim for audit purposes.









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


  
## Plan for Input Sanitizing and Guard Token-Claim Hardening


input_sanitizing:
    - id: 1
      title: Request body size limits (Keep and Guard HTTP servers)
      details: Add http.MaxBytesReader at the start of every handler that decodes a request body.
      constants:
        keep:
          name: maxRequestBodyBytes
          value: 1 << 20
          bytes: 1048576
          note: covers large Arguments maps
        guard:
          name: maxRequestBodyBytes
          value: 512 << 10
          bytes: 524288
          note: no tool arguments, only JWTs and small payloads
      note:
        - these restrictions should be in the config file, not hard-coded
        - 1048576 and 524288 are reasonable defaults 
        - normalize server.go structure first, if needed

    - id: 2
      title: String field length caps (Keep and Guard)
      details: Define a set of constants and validate after decoding.
      limits:
        server_name_bytes: 256
        tool_name_bytes: 256
        user_id_bytes: 512
        trace_id_bytes: 128
        session_id_bytes: 128
        reason_bytes: 4096
        jti_bytes: 128
        pending_jwt_bytes: 8192
        scope_override_bytes: 16384                
      rationale:
        server_name_tool_name: no legitimate tool name is longer
        trace_id_session_id: UUIDs are 36 chars; leave headroom for other formats
        reason: enough for any human-readable explanation
        jti: UUIDs are 36 chars
      applied_in:
        keep:
          - handleCall
          - handleAuthorize
          - handleLog
        guard:
          - handlePending
          - handleTokenDeposit
          - handleTokenClaim
      notes:
        - the limits above should be the defaults, but it should be possible to override them in the config files

    - id: 3
      title: Decision field enum validation in handleLog
      details: Gate sends decision log entries to Keep.
      validate:
        field: decision
        allowed:
          - allow
          - deny
          - escalate
          - workflow
        on_invalid: reject individual records that are invalid, process the rest

    - id: 4
      title: Unclaimed-token list size cap
      details: pendingRequests and unclaimedTokens in Guard currently have no size limits.
      cap:
        per_user_entries: 10000
        total_entries: 100000
        on_exceeded: return 503
      notes:
        - the 10,000 and 100,000 entry restrictions should be in the config file, 
          with 10000 and 100000 as defaults
        - those entry caps should only apply if we're holding the tokens in memory. If we're
          using a distributed cache, we'll let the cache enforce its own limits
      

guard_token_claim_surface:
    - id: 5
      title: Require auth by default on token APIs
      details:
        - Change requireTokenAuth to deny by default when cfg.Auth.BearerToken == "".
        - Add config field auth.allow_unauthenticated_token_apis: true to explicitly re-enable open posture for development.
        - Emit a loud slog.Warn at startup if allow_unauthenticated_token_apis is set.
        - Update config validation to error when Guard has no bearer token and this flag is not set.
          - errors here should cause Guard to fail-fast, which is the intended behavior if there's no bearer token
            and API calls without a bearer token are denied
      notes:
        - this excludes `/token/claim` , which does not require a bearer token

    - id: 6
      title: Update the response data for /token/unclaimed/list
      details:
        - Return the raw JWT, jti, and expires_at.
        - Gate will need to be modified to expect expires_at

    - id: 7
      title: Log requester IP on token claim
      details:
        - handleTokenClaim already logs claim events.
        - Add r.RemoteAddr to the slog entry for audit value.

not_proposed:
    - Rate limiting (needs a storage design decision: in-memory vs Redis; deferred)
    - Tool argument content inspection (belongs to PDP, not sanitizing)
    - Argument map depth limits (complexity is high; body size limit covers worst case)




