

# Phase 3 / Future

Some of these tasks were deferred from Phase 2 because they are complicated and involve access to potentially expensive cloud resources

Some of these tasks are 


### Task: Support Cloud Vaults (Phase 3)
    These require importing heavy cloud-provider SDKs (AWS/GCP/Azure) and setting up complex test environments. By deferring them, we
    keep the scope of the first release a little more manageable

    1. awssec://: AWS Secrets Manager.
    2. gcpsec://: GCP Secret Manager.
    3. azkv://: Azure Key Vault.

    - priority: low
    - comment: this is potentially expensive to implement, and it make sense to wait until we actually see someone using this solution


### Task: Add distributed caching to the Portcullis-Guard
allow multiple Portcullis-Guard instances to share a common distributed memory system (such as Redis)

### Task: Allow Portcullis-Keep to add extra data to MCP server calls
if the MCP server requires a secret or some sort of certificate in order to accept MCP requests, Keep can be
modified 


### Task: Routing model for Portcullis-Keep and Workflows
when the PDP generates a 'workflow' response, the important information should be
sent to the appropriate workflow system to allow for authorization. But it is quite possible
that in a large organization, different workflow systems will be used to authorize
different types of requests - for example, by MCP, or even perhaps by Tool.

We need to modify the Keep config to allow different workflow plugins to be invoked
for different service / tool combos 

- priority: low
- comment: this is probably interesting, but we don't have any enterprise-scale workflow tools to use for testing purposes, which makes this
           challenging to design, difficult to implement and impossible to test




### Task: Acquire Human Credentials (at Portcullis-Gate)
- [x] Token file (Option B) — Gate reads `identity.oidc.token_file`; fails hard (no OS fallback) when source is "oidc" and token is missing or invalid; `~` is now expanded correctly on read
- [ ] Keychain storage — optional future  source of identity
- [ ] Certificate - optional future source of identity
- [ ] Device authorization grant (RFC 8628) — probably not necessary
- priority: low
- comment: different organizations have different ways of providing identity. Would prefer to wait for feedback before trying to implement specific additional identity sources



### Task: add streamable-http access for Portcullis-Gate, so it can support multiple agents in parallel
i.e. instead of running as a stdio MCP, it can run as an autonomous local process.
- IMPORTANT! Portcullis-Gate would need to be concurrency-safe
- priority: low
- comment: it makes sense to wait until we see organizations encountering this issue and preferring a standalone streaming-http solution over a set of stdio solutions listening on different ports


### Task: Optionally create a Portcullis-Gate API to collect the list of DENY responses, along with trace/session information
not sure if this is necessary. It might be helpful for troubleshooting
- priority: very low
- comment: not sure if the juice is worth the squeeze


### Task: Add a login capability to Portcullis-Guard
This would potentially prevent a particularly nasty rogue agent from knowingly creating a request that would require escalation, waiting for the response, abusing some sort of direct HTTP mechanism to edit and approve the request, and then trying again, without the user being aware that it was happening.

This can probably be done just by editing the template, without any structural changes to Portculis-Guard.  TBD.

### Task: Allow the 'edit' capability for escalation claims to be turned on and off by configuration
This should be straightforward - the edit capability is already on a templated web page, so it should
be easy enough to remove the edit option via template rules

### Task: Consider some mechanism to explain the escalation claims in human language
This might be very tricky, given how complex some MCP requests can be.

### Task: Configuration option to disable the Portcullis-Gate web page, thus eliminating port contention

### Task: Potential for limited-use of the escalation tokens at Portcullis-Gate
Configuration option at Portculils-Gate to allow escalation tokens to be used a limited number of times before being automatically deleted

### Task: Enrich the capabilities of portcullis-localfs policy
Allow IT to configure the policy to allow for local writes, deletes, et al, to certain directory trees without checking agains Portcullis-Keep

### Task: Add performance monitoring to Portcullis-Keep
Use the OpenTelemetry wrapper around HTTP calls to get detailed measurements



### Task: Guard-native OIDC login
for organizations that don't want to use SSO proxies to protect the human-focused endpoint(s) of Portcullis-Guard, we could implement
a login interface



