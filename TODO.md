# Phase 2

## Tasks






### ~~Task: Include the traceid in the Deny, Escalate and Workflow EnrichedMCPResponse message from Keep -> Gate~~ (done)
- Keep now includes `trace_id` in all 202 escalate/workflow bodies (deny 403 already had it)
- `shared.DenyError` carries reason + trace_id from Keep's 403 body; unwraps to `ErrDenied`
- `shared.EscalationPendingError` gains `TraceID` field; forwarder decodes it from 202 body

### ~~Task: Customize messaging for Deny / Escalate / Workflow~~ (done)
- `agent.deny.instructions` config field; supports `{reason}` and `{trace_id}` placeholders
- `agent.approval.instructions` updated to also support `{trace_id}`
- IT team includes or omits placeholders to control what the agent sees








------------------------------------------------------------------------------------


# Phase 3 / Future



### Task: Support Cloud Vaults (Phase 3)
    These require importing heavy cloud-provider SDKs (AWS/GCP/Azure) and setting up complex test environments. By deferring them, we
    keep the scope of the first release a little more manageable

    1. awssec://: AWS Secrets Manager.
    2. gcpsec://: GCP Secret Manager.
    3. azkv://: Azure Key Vault.

    - priority: low



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
- [ ] Keychain storage — optional future  source of identity
- [ ] Certificate - optional future source of identity
- [ ] Device authorization grant (RFC 8628) — probably not necessary
- priority: low



### Task: add streamable-http access for Gate, so it can support multiple agents in parallel
i.e. instead of running as a stdio MCP, it can run as an autonomous local process.
- IMPORTANT! Portcullis-Gate would need to be concurrency-safe
- priority: low


### Task: Optionally create a Gate API to collect the list of DENY responses, along with trace/session information
not sure if this is necessary. It might be helpful for troubleshooting
- priority: very low




## Implementation notes


  
