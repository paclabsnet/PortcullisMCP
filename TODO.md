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

### Task: Plugabble Logging
- We need Keep to support multiple decision logging strategies
- perhaps some sort of LogSink interface with multiple destinations?
- priority: medium

### Task: Fix Escalation URL (Short JTI URL via Gate→Guard JWT Push)
- **Problem**: Keep embeds the full escalation request JWT in the approval URL (`?token=<jwt>`). The JWT is ~500 chars and AI clients (e.g. Claude Desktop) occasionally mangle it, producing invalid signatures.
- **Fix**: Gate pushes the JWT directly to Guard via a new `POST /pending` endpoint; approval URL is shortened to `?jti=<uuid>` only.
- **Security**: Guard must validate the JWT signature on receipt (using its existing `keepKey`) to prevent a rogue Gate instance from registering arbitrary JWTs and granting itself escalation tokens.
- **Implementation scope**:
  - `shared/types.go` — add `EscalationJWT string` to `EscalationPendingError`
  - `keep/server.go` — add `escalation_jwt` (raw signed JWT) to 202 response body alongside `escalation_jti`; remove `workflow_reference` from 202 body (Gate builds the URL itself)
  - `gate/forwarder.go` — decode `escalation_jwt` from 202 body and populate `EscalationPendingError.EscalationJWT`
  - `gate/guardclient.go` — add `RegisterPending(ctx, jti, jwt string) error` calling new `POST /pending`
  - `gate/config.go` — add `EscalationMessage string` to `GuardConfig` (configurable message template shown to agent)
  - `gate/server.go` — on User-authority escalation: call `RegisterPending`; build short URL as `{guard.endpoint}/approve?jti={jti}`; format message using `EscalationMessage` template (or default)
  - `guard/server.go` — add `POST /pending` handler: validate JWT signature, store JWT keyed by JTI; update `handleGet` to accept `?jti=` (lookup stored JWT by JTI) in addition to or instead of `?token=`
- **Default message template**: `"Escalation required: {reason}\n\nApprove at: {url}"`
- priority: high

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


