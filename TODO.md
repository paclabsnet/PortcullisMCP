# Phase 2

## Tasks






### Task: Include the traceid in the Deny, Escalate and Workflow EnrichedMCPResponse message from Keep -> Gate
Allows a user to escalate to the enterprise security team if they aren't allowed to do something they think they should be able to
- priority: low


### Task: Customize messaging for Deny / Escalate / Workflow
The messaging that Portcullis-Gate uses to tell the Agent what has happened in a Deny / Escalate / Workflow response
should be pulled from the config, with a sensible default.  
- priority: low








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


  
