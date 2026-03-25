# Phase 2

## Tasks




### Task: Improve API
- We need to version Keep's API with Gate, or version the Wrapped MCP Request, or both, so we know what to expect in the contents
- We need to version the logging API (how Gate sends logs to Keep)
- priority: high , but only after we've gotten all of the core communications done, no need in versioning our API too early




### Task: Implement "Mock Workflow" Loopback for System Authority Testing
- **Problem**: Testing "System Authority" (workflow approvals like ServiceNow) is difficult without a real enterprise installation or a mock workflow tool.
- **Fix**: Create a "Mock Workflow Handler" that uses the existing Webhook flow to simulate an enterprise approval loop.
- **Implementation scope**:
  - `examples/mock-workflow-server/main.go` — A tiny HTTP server that:
    1. Receives a webhook from Keep containing the `pending_jwt`.
    2. Logs the request and "sleeps" for a configurable delay (e.g., 5-10 seconds).
    3. Calls Guard's `POST /token/deposit` with the `pending_jwt` and `user_id`.
  - Documentation/YAML — Provide a `keep-config.mock-workflow.yaml` that uses the `webhook` handler to point at this mock server.
- **Benefit**: Allows end-to-end verification of the System Authority flow (Keep -> Webhook -> Guard -> Gate Polling) without real infrastructure.
- priority: medium-high


#### Proposed Implementation Plan:


  Operation:
   1. Parse GUARD_URL, GUARD_TOKEN, APPROVAL_DELAY, and PORT from environment.
   2. Listen: POST /webhook (configured in Keep's keep-config.mock-workflow.yaml).
   3. Process:
       * collect the pending_jwt
         * no need to verify that it was signed by Keep, since that would require this workflow server to know Keep's secret, and Guard will validate the pending JWT anyways
         * pull the UserID from the pending_jwt claims
       * Log the incoming trace_id and UserID
       * Respond 200 OK immediately to Keep (releasing its connection).
   4. Asynchronous Step (Goroutine):
       * Sleep for APPROVAL_DELAY (e.g., 5 seconds).
       * Deposit: POST to Guard's /token/deposit using:
           * pending_jwt: (the Keep-signed request JWT).
           * user_id: (the extracted/verified UID).
           * Auth: Includes the Authorization: Bearer <GUARD_TOKEN> header.
   5. Test Configuration (config/keep-config.mock-workflow.yaml):
       * Set escalation.workflow.type to webhook.
       * Set webhook.url to http://localhost:<PORT>/webhook.






### Task: JWT Naming Alignment 
  - Rename escalation_jwt to pending_jwt in internal/keep/workflow_webhook.go and internal/keep/server.go to achieve perfect consistency across the codebase.
  - priority: medium


### Task: Improve Secret Management
- We probably need to support a way to gather secrets (Private keys, shared secrets) from a vault, but don't get rid of the config option for the sandbox model
- priority: medium







### Task: Plugabble Logging
- We need Keep to support multiple decision logging strategies
- perhaps some sort of LogSink interface with multiple destinations?
- priority: medium


### Task: set enterprise logging configuration to redact
- all keys should be redacted
- some commonly useful keys should be included in the config, but commented out
- priority: medium


### Task: Input sanitizing at Keep and Guard
- standard good hygiene

- medium-low priority



### Task: add http for gate, so it can support multiple agents in parallel
i.e. instead of running as a stdio MCP, it can run as an autonomous local process.
- Portcullis-Gate needs to be concurrency-safe
- priority: medium-low



### Task: System Authority Escalation
- Enterprises will need both User-authority escalations (user approves in seconds via Guard) and System-authority escalations (ServiceNow/Jira/etc. approves over hours/days)
- The PDP determines the authority based on risk level, user role, and tool
- **User authority**: Gate gets `escalation_jti` + `escalation_jwt`, pushes JWT to Guard, stores pending entry by JTI; retry path and 60s poll both apply
- **System authority**: Gate gets workflow metadata only (reference URL, ticket ID, SLA, etc.), no JTI; presents metadata to agent via configurable message template; no pending entry stored; 60s poll is the only collection path (acceptable given approval latency)
- When a System workflow approves, it calls Guard's `/token/deposit`; Gate picks up the resulting token on next poll
- Implementation scope: `shared/types.go` (add `Authority`, `EscalationJWT`, `WorkflowMetadata` to `EscalationPendingError`), `keep/server.go` (add `authority` + `escalation_jwt` to 202 body), `gate/config.go` (add per-authority message templates), `gate/forwarder.go`, `gate/server.go` (split behavior by authority), `gate/guardclient.go` (add `RegisterPending`), `guard/server.go` (add `POST /pending`, change `handleGet` to `?jti=` lookup)
- priority: low
- notes: this is difficult to do without an actual enterprise deployment to test against, and even then it will be much different. 
- the interesting thing here in the short term is how to create a plugin model where we can create enterprise-specific system workflow interfaces, without having to change the core code of Portcullis (which will help with support and platform stability)






### Task: Acquire Human Credentials (at Gate)
- [x] Token file (Option B) — Gate reads `identity.oidc.token_file`; fails hard (no OS fallback) when source is "oidc" and token is missing or invalid; `~` is now expanded correctly on read
- [ ] Keychain storage — optional future enhancement
- [ ] Device authorization grant (RFC 8628) — fallback for when no token file exists; deferred until enterprise adoption confirmed (see Implementation Details below)
- priority: low


### Task: Fail closed for Gate if Keep is unavailable
- this is not super important, since if Keep is down, no non-local MCP requests can occur
- Basically, ensure that Gate indicates to the user that the Portcullis server is not available right now, try again later.
- low priority


### Task: Optionally Include the traceid in the Deny, Escalate and Workflow messages back to the user
- purpose: allows a user to escalate to the enterprise security team if they aren't allowed to do something they think they should be able to
- low priority





### Task: When PDP responds with Workflow, it can specify a provider?
Discuss - right now, the PDP will just respond with 'workflow'.  Which is fine, but what if
different workflow escalation scenarios demand different workflows? 

We have two options
- keep configuration defines the workflow per server/tool
- the PDP defines the workflow per server/tool

The benefit of the PDP doing it is that it's a modification to policy logic and/or data, not to the Keep configuration.  I'm not sure if that's necessarily better or worse, I suppose it can be a configuration
option

priority: low





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

- priority: low




### Task: Optionally create a Gate API to collect the list of DENY responses, along with trace/session information
- not sure if this is necessary. It might be helpful for troubleshooting
- very low priority


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





