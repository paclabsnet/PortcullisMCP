# Phase 2

## Tasks




### Task: Improve API
- We need to version Keep's API with Gate, or version the Wrapped MCP Request, or both, so we know what to expect in the contents
- We need to version the logging API (how Gate sends logs to Keep)
- priority: high , but only after we've gotten all of the core communications done, no need in versioning our API too early


### Task: handle the 'workflow' response from the PDP [DONE]
- when the PDP returns 'workflow' as a response, Keep must mint the PendingJWT as normal, but invoke the
  escalation.workflow configuration to process the PendingJWT and invoke an external workflow
- if no workflow handler is configured or resolvable for the request, Keep should treat this as a deny, with a message
  indicating that this request could be authorized, but there is no workflow configured to do so.


### Task: Implement "Mock Workflow" Loopback for System Workflow Simulation [DONE]
- **Problem**: Testing "System Workflow" (workflow approvals like ServiceNow) is difficult without a real enterprise installation or a mock workflow tool.
- **Fix**: Create a "Mock Workflow Handler" that uses the existing Webhook flow to simulate an enterprise approval loop.
- **Implementation scope**:
  - `examples/mock-workflow-server/main.go` — A tiny HTTP server that:
    1. Receives a webhook from Keep containing the `pending_jwt`.
    2. Logs the request and "sleeps" for a configurable delay (e.g., 5-10 seconds).
    3. Calls Guard's `POST /token/deposit` with the `pending_jwt` and `user_id`.
  - Documentation/YAML — Provide a `keep-config.mock-workflow.yaml` that uses the `webhook` handler to point at this mock server.
- **Benefit**: Allows end-to-end verification of an "Out of Band" Workflow Approval flow (Keep -> Webhook -> Guard -> Gate Polling) without real infrastructure.
- priority: medium-high


#### Proposed Implementation Plan:

  Operation:
   1. Parse GUARD_URL, GUARD_TOKEN, APPROVAL_DELAY, and PORT from environment.
   2. Listen: POST /webhook (configured in Keep's keep-config.mock-workflow.yaml).
   3. Process:
       * collect the pending_jwt and UserID from the POST
         * no need to verify that it was signed by Keep, since that would require this 
           workflow server to know Keep's secret, and Guard will validate the pending JWT anyways
       * Log the incoming trace_id and UserID
       * Respond 200 OK immediately to Keep (releasing its connection).
   4. Asynchronous Step (Goroutine):
       * Sleep for APPROVAL_DELAY (e.g., 5 seconds).
       * Deposit: POST to Guard's /token/deposit using:
           * pending_jwt: (the Keep-signed request JWT).
           * user_id: (the UserID provided in the original POST)
             * Portcullis-Guard will validate this UserID against the one in the JWT, so we don't have to do that here
           * Auth: Includes the Authorization: Bearer <GUARD_TOKEN> header.
   5. Test Configuration (config/keep-config.mock-workflow.yaml):
       * Set escalation.workflow.type to webhook.
       * Set webhook.url to http://localhost:<PORT>/webhook.






### Task: JWT Naming Alignment [DONE]
  - Renamed `escalation_jwt` → `pending_jwt` (JSON key) and `EscalationJWT` → `PendingJWT` (Go field) everywhere the Keep-signed pending request JWT appears: keep/server.go, keep/workflow_webhook.go, gate/forwarder.go, shared/types.go, and all associated tests. Guard already used `pending_jwt` at /token/deposit. The Guard-issued escalation token (EscalationToken/EscalationTokens) was left untouched.


### Task: Improve Secret Management
- We probably need to support a way to gather secrets (Private keys, shared secrets) from a vault, but don't get rid of the config option for the sandbox model
- priority: medium







### Task: Pluggable Logging
- We need Keep to support multiple decision logging strategies
- perhaps some sort of LogSink interface with multiple destinations?
- priority: medium


### Task: set enterprise logging configuration to redact
- all keys should be redacted
- some commonly useful keys should be included in the config, but commented out
- it makes sense to do this at the same time as Pluggable Logging
- priority: medium


### Task: Input sanitizing at Keep and Guard
- standard good hygiene
- medium-low priority



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
- [ ] Device authorization grant (RFC 8628) — fallback for when no token file exists; deferred until enterprise adoption confirmed (see Implementation Details below)
- priority: low


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




