# Phase 2

## Tasks

### Task: Update 'Reason' when creating escalation tokens
Currently the reason field for the JWTs is echoing the problem. It should probably be more like reason: "User <X> has approved a temporary escalation of privileges for the Agent" or something like that.


### Task: Improve API
- We need to version Keep's API with Gate, or version the Wrapped MCP Request, or both, so we know what to expect in the contents
- We need to version the logging API (how Gate sends logs to Keep)

### Task: Improve Secret Management
- We probably need to support a way to gather secrets (Private keys, shared secrets) from a vault, but don't get rid of the config option for the sandbox model
- priority: medium


### Task: User-Friendly error handling at Gate
The Gate is customer facing, launched by an Agent, and interacts with the Agent via MCP calls.
Gate should not shut down when it has an error, because it will be difficult, if not impossible
for a normal user to understand what is going on. 

Instead, if there are any configuration errors or validation errors or network errors, or any other error in Gate
that prevents it from functioning normally, it should move into 'Degraded mode' where it responds to every MCP
request with an error message describing the problem. This will dramatically improve the user experience when
Gate is misconfigured

  Benefits
   * Observability: The user gets immediate, actionable feedback in their primary workspace (the AI chat).
   * Resilience: Gate remains "connected" to the Agent, preventing the Agent from giving up on the server entirely.
   * Compliance: As per your requirement, if the OIDC token is missing, Gate successfully blocks all work but explains why.

   

### Task: Harden Configuration and Error Handling (Fail Fast)
- **Problem**: The system is currently too permissive. Typos in YAML (e.g., `signing_key` vs `signing-key`) are silently ignored by the default decoder, and missing critical security components (like signing keys or OIDC providers) often result in a "degraded" startup with logged warnings rather than a fatal exit.
- **Fix**: Implement strict validation at startup to ensure the system never runs in an insecure or broken state.
- **Implementation scope**:
  - `config/*.go` — add `Validate() error` methods to all configuration structs (Check for empty endpoints, missing keys, invalid TTLs).
  - `cmd/*/main.go` — switch to `yaml.NewDecoder(r).KnownFields(true).Decode(&cfg)` to catch misspelled configuration keys at parse time.
  - `internal/keep/server.go` — make `EscalationSigner` initialization failure fatal if a signing key is provided but invalid.
  - `internal/guard/server.go` — validate `Keep` public key and `Guard` private key immediately on `NewServer`.
  - `internal/gate/server.go` — ensure background workers (like `pollGuardWorker`) can intelligently handle network errors. Retry thoughtfully, log appropriately. Communicate to the user appropriately. Never let a worker block main shutdown. auto-recover when the network issues improve.  Don't overlog for network errors, which just causes noise
- priority: high


#### Harden Configuration and Error Handling (Fail Fast) Plan and Analysis

1. Strict Decoding: Update cmd/portcullis-gate/main.go, cmd/portcullis-guard/main.go, and cmd/portcullis-keep/main.go to use
  yaml.NewDecoder(r).KnownFields(true). This catches typos in configuration keys at startup.
2. Config Validation: Implement a Validate() error method on the Config structs in:
    * internal/gate/config.go (Check for missing Keep/Guard endpoints, invalid OIDC settings).
    * internal/guard/config.go (Check for missing signing keys and listen address).
    * internal/keep/config.go (Check for PDP endpoint and identity normalization settings).
3. Fatal on Startup: Update the main.go entry points to call Validate() and os.Exit(1) if validation fails.

Concerns:
- Suggestion: treat the TODO as delta work, not net-new everywhere
- The plan line about making background workers signal terminal failures is risky for Gate. 
- Guard polling currently treats outages as warnings in server.go:568, which is usually correct for transient network/auth blips.
- Concern: killing Gate on temporary Guard/API failures could reduce availability more than it improves security.
  - Better split:
    - Startup config/key/TLS errors: fatal.
    - Runtime dependency outages: degrade with clear errors/metrics, do not crash loop.
- If you add Validate methods, avoid duplicating checks in two places with different messages/rules.
- KnownFields catches unknown struct fields, but not semantic issues inside maps..
  - You still need explicit Validate rules for value-level correctness (URLs, TTL bounds, required combinations).
- Portcullis-Keep admin reload reads full config via strict loader in server.go:462, but only applies backends in server.go:458
  - operators may be surprised that a typo in an unrelated section blocks backend reload
  - Not a blocker, just document this clearly.

Narrow the task to:
- Guard strict decode + Validate + startup Validate call.
- Keep Validate + startup Validate call (decoding already strict).
- Gate strict decode migration (it still uses unmarshal) in main.go:79.
- Clear policy for startup-fatal vs runtime-degraded failures.  


Good default policy:
- Startup: strict/fatal on invalid config/keys/TLS.
- Runtime workers: degrade service mode, keep process running, report health and errors, auto-recover when dependencies return.


Other specific items
- if the guard configuration is not available in the Gate configuration, the Gate cannot perform escalation, so it should treat an escalate response as the equiavelent of a deny response
- if the source is OIDC, the token file must exist for Gate to perform any MCP work.  If the OIDC token does not exist, every MCP call must return an error indicating that the MCP can't perform any work because the identity of the user is unknown.
- Configuration-based failures (Auth, Malformed URLs) in background workers should be caught during the New() constructor, before the
     worker even starts. This keeps the worker logic simple (just retries for transient network issues) and ensures the "Fail-Fast"
     happens at the very beginning of main().
- validating the format of HMAC/RSA keys is out of scope.  If they are mal-formed, the system will discover that problem on first use, which is fine.
- Validate() for YAML files must run after environment variable expansion to ensure the final, expanded values are correct



### Task: Implement Health and Liveness Endpoints (Observability)
- **Problem**: Keep and Guard currently lack standard `/health` and `/ready` endpoints. Orchestrators (Kubernetes, Docker, systemd) cannot distinguish between a service that is starting up, a service that is healthy, and a service that has a "dead" internal component (e.g., failed OPA engine or invalid signing key).
- **Fix**: Add dedicated health check handlers to both Keep and Guard.
- **Implementation scope**:
  - `internal/keep/server.go` — Add `GET /healthz` (liveness) and `GET /readyz` (readiness). Readiness should verify the PDP is loaded and the Escalate Signer is initialized.
  - `internal/guard/server.go` — Add `GET /healthz` and `GET /readyz`. Readiness should verify signing keys are loaded and templates are parsed.
- priority: medium-high

### Task: Plugabble Logging
- We need Keep to support multiple decision logging strategies
- perhaps some sort of LogSink interface with multiple destinations?
- priority: medium



### Task: System Authority Escalation
- Enterprises will need both User-authority escalations (user approves in seconds via Guard) and System-authority escalations (ServiceNow/Jira/etc. approves over hours/days)
- The PDP determines the authority based on risk level, user role, and tool
- **User authority**: Gate gets `escalation_jti` + `escalation_jwt`, pushes JWT to Guard, stores pending entry by JTI; retry path and 60s poll both apply
- **System authority**: Gate gets workflow metadata only (reference URL, ticket ID, SLA, etc.), no JTI; presents metadata to agent via configurable message template; no pending entry stored; 60s poll is the only collection path (acceptable given approval latency)
- When a System workflow approves, it calls Guard's `/token/deposit`; Gate picks up the resulting token on next poll
- Implementation scope: `shared/types.go` (add `Authority`, `EscalationJWT`, `WorkflowMetadata` to `EscalationPendingError`), `keep/server.go` (add `authority` + `escalation_jwt` to 202 body), `gate/config.go` (add per-authority message templates), `gate/forwarder.go`, `gate/server.go` (split behavior by authority), `gate/guardclient.go` (add `RegisterPending`), `guard/server.go` (add `POST /pending`, change `handleGet` to `?jti=` lookup)
- priority: medium

### Task: Acquire Human Credentials (at Gate)
- [x] Token file (Option B) — Gate reads `identity.oidc.token_file`; fails hard (no OS fallback) when source is "oidc" and token is missing or invalid; `~` is now expanded correctly on read
- [ ] Keychain storage — optional future enhancement
- [ ] Device authorization grant (RFC 8628) — fallback for when no token file exists; deferred until enterprise adoption confirmed (see Implementation Details below)
- priority: medium-high


### Task: Fail closed for Gate if Keep is unavailable
- this is not super important, since if Keep is down, no non-local MCP requests can occur
- Basically, ensure that Gate indicates to the user that the Portcullis server is not available right now, try again later.
- low priority


### Task: Optionally Include the traceid in the Deny, Escalate and Workflow messages back to the user
- purpose: allows a user to escalate to the enterprise security team if they aren't allowed to do something they think they should be able to
- low priority

### Task: Optionally create a Gate API to collect the list of DENY responses, along with trace/session information
- not sure if this is necessary. It might be helpful for troubleshooting
- very low priority




### Task: When PDP responds with Workflow, it can specify a provider?
Discuss - right now, the PDP will just respond with 'workflow'.  Which is fine, but what if
different workflow escalation scenarios demand different workflows? 

We have two options
- keep configuration defines the workflow per server/tool
- the PDP defines the workflow per server/tool

The benefit of the PDP doing it is that it's a modification to policy logic and/or data, not to the Keep configuration.  I'm not sure if that's necessarily better or worse, I suppose it can be a configuration
option

priority: low



### Task: Input sanitizing at Keep and Guard
- standard good hygiene

- medium-low priority


### Task: set enterprise logging configuration to redact
- all keys should be redacted
- some commonly useful keys should be commented out

### Task: add http for gate, so it can support multiple agents in parallel
i.e. instead of running as a stdio MCP, it can run as an autonomous local process.
- Portcullis-Gate needs to be concurrency-safe


### Task: 'Workflow' response from PDP
In addition to 'allow', 'deny' and 'escalate', we will add 'workflow' as a viable response from the PDP.

When the PDP responds with 'workflow', this should tell Keep to invoke ServiceNow or some other tool to make the necessary approvals.

Need more research:
- does Keep send the same JWT to the workflow tool?  Or does it send the key elements of
  the JSON, and let the workflow tool handle the details? Or is this something that is an 
  implementation detail of the appropriate workflow provider (YES)
- it seems more secure to send a JWT, because that way there's evidence that the request
  was created properly by the system flow.  But on the other hand, this requires the workflow 
  tool to be able to process and  validate JWTs
- perhaps this should be configurable?





## Implementation notes


  
### Acquire Human Credentials

#### Option A: Device Authorization Grant (RFC 8628)
  Gate initiates auth by calling the IdP's device authorization endpoint. The IdP returns a short user code and a URL. Gate prints (or surfaces via the agent) something like:

  "Visit https://login.enterprise.com/activate and enter code: WXYZ-1234"                                                             

  The user visits that URL on any browser, any device. Gate polls the IdP token endpoint until the user completes it. No redirect URI, no localhost web server at all.

  This is how gh auth login, az login, and most CLI tools handle this today. 

#### Option B: Enterprise-injected token file (already in your design)
  The config already has token file: "~/.portcullis/oidc-token". The enterprise deploys an SSO agent (Okta Device Trust, a custom
  refresh daemon, etc.) that keeps this file current. Gate reads it. Gate never touches OAuth at all.                              
  This is the right answer for a mature enterprise deployment where the org already manages endpoint identity.                     


#### Recommendation for Portcullis:
  Why not both?
  1. Token file — primary, enterprise-managed, zero Gate complexity
  2. Device flow — fallback when no valid token file exists; works everywhere, no localhost trust issues, fits the CLI/daemon model





## Security Review

1. High: Escalation request JWT is propagated through URLs and external workflow payloads
- URL embedding in query string: workflow_url.go:44
- Agent message explicitly asks to pass the full approval URL: types.go:113
- Webhook payload includes full escalation JWT: workflow_webhook.go:51
- ServiceNow description includes full escalation JWT: workflow_servicenow.go:58
  Why this is major:
  - Query strings and ticket fields are commonly copied, logged, indexed, and retained.
  - That increases exposure of signed escalation artifacts across systems and operators.

  Suggested direction:
  - Move to short reference flow (JTI/state handle), keep signed JWT server-to-server only, and avoid sending JWT in browser-visible URLs and ticket text.

2. High: Guard token-claim surface is capability-based and can be open depending on config
- Claim endpoint intentionally unauthenticated: server.go:139
- Guard can run with no bearer token protection for token APIs: server.go:385
- Unclaimed-list response includes raw token material: server.go:414
  
Why this is major:
- Security posture depends heavily on deployment hardening.
- In permissive deployments, token retrieval paths expose high-value artifacts.

Suggested direction:
- Require auth by default for token APIs, return only metadata from list endpoints, and keep raw token retrieval tightly scoped/authenticated.





