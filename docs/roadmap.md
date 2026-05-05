# Phase 3

Some of these tasks were deferred from Phase 2 because they are complicated and involve access to potentially expensive
cloud resources

### Task: allow for Keep to act as a direct proxy for some MCPs, instead of having to go through Gate

For a lot of third-party MCPs, the tool/list is gated behind OAuth. So Keep can't get the list directly, and will have to use
a static list.  This is ok, because we need policy rules for accessing the tools anyways.

But a static list is not ideal, and other MCP proxy gateway vendors have designed their systems to act as direct proxies
for multiple independent third-party MCPs.  This was not the original vision for Portcullis, but it absolutely can work if
we want it to - the agents are configured with the address of Keep, with an appropriate URL for the MCP, and Keep listens on
that endpoint for access to a particular remote MCP. Using Figma as an example:

* Keep admins add Figma as a proxied MCP, with a local endpoint and a remote URL for Figma
* Keep policy writers discover and create policy rules for Figma
* Agents are configured to use the Keep URL for Figma
* Agents start up, query the Keep URL for Figma.  
  * Agent sends that request to the Keep proxy.
  * Keep passes that request along to the true Figma MCP
  * Figma responds with an OAuth request
  * Keep passes that OAuth request back to the user
  * The user authenticates, and repeats the request
  * Keep passes that request along to the true Figma MCP
  * Figma answers with a tool list
  * Keep sends the tool list back to the Agent
  * Agent now has the tool list for doing stuff with Figma

#### Key implementation questions

1. Keep needs to pass headers on to Figma?  or is the OAuth stuff going to be in the JSON body?
2. Keep needs to have a policy rule about fetching tool lists from remote MCPs
3. Keep will need policy rules for the individual MCP tools offered by the remote MCP (since they fail by default)

#### Interesting challenges

1. Keep won't know about the identity of the user in this scenario, so the policy rules will need to be much simpler
2. Primarily, this will be valuable as a decision log, and disabling some specific tools
3. If the organization wants fine-grained authorization, they need the request to be managed by Gate, which requires either a
   static tool list, or a tool list that can be fetched with a long-lived token

- priority: high


### Task: Support 'escalate' in multi-tenant environments
Providing a way for a user of an AI-enabled console to escalate privileges for an AI Agent is tricky, and we need time to figure out how to explain the approval process to the user.

priority: medium

### Task: Gate should keep track of 'unused' escalation approval URLs for a time
When Gate receives an `escalate` response and passes that on to the Agent, there's no guarantee that the Agent will provide the link to the user.  We can include the link in the Gate management UI.  If the user creates the appropriate escalation-token, that's evidence that we can remove the link from the management UI.

priority: medium

### Task: production YAML should not support unknown keys in the responsibility section

If the portcullis-localfs tool configuration is incorrect, it could allow the agent access to sensitive
areas of the user's filesystem.  Ensuring that there are no unknown keys in the config YAML will 
help avoid that issue.

- priority: very low

2026-05-05 : I have no idea what this means. What are unknown keys in this context???


### Task: Support vault:// secret resolution for map[string]string config fields

The secret resolver walks named struct fields via dot-notation and resolves secret
URIs (`vault://`, `envvar://`, etc.) in string values. It does not currently traverse
`map[string]string` values, so fields like `decision_logs.headers` and
`webhook.headers` cannot use vault:// or envvar:// for individual header values
(e.g. `Authorization: "envvar://SIEM_TOKEN"`).

The example configs document this limitation with a note directing operators to
populate these fields from external secrets tooling before startup.

The fix is to extend the resolver to walk map values and apply secret resolution
to each entry, subject to the same allowlist rules. Both Keep's
`decision_logs.headers` and `webhook.headers` (and any future map-valued fields)
would benefit.

- priority: medium-high






### Task: Support Cloud Vaults
These require importing heavy cloud-provider SDKs (AWS/GCP/Azure) and setting up complex test environments. By deferring
them, we
keep the scope of the first release a little more manageable

1. awssec://: AWS Secrets Manager.
2. gcpsec://: GCP Secret Manager.
3. azkv://: Azure Key Vault.

- priority: low
- comment: this is potentially expensive to implement, and it make sense to wait until we actually see someone using
  this solution
- comment: also, these names aren't standard, so we have to write adapters in any case




### Task: Routing model for Portcullis-Keep and Workflows
when the PDP generates a 'workflow' response, the important information should be
sent to the appropriate workflow system to allow for authorization. But it is quite possible
that in a large organization, different workflow systems will be used to authorize
different types of requests - for example, by MCP, or even perhaps by Tool.

We need to modify the Keep config to allow different workflow plugins to be invoked
for different service / tool combos

- priority: low
- comment: this is probably interesting, but we don't have any enterprise-scale 
  workflow tools to use for testing purposes, which makes this challenging to design, difficult to implement and impossible to test




### Task: Acquire Human Credentials (at Portcullis-Gate)
- [x] OIDC login - Gate (via the Agent) sends the user to a login page and accepts the oidc-token as a callback
  after a successful login.
- [x] Token file — Gate reads `identity.oidc.token_file`; fails hard (no OS fallback)
  when source is "oidc" and token is missing or invalid; `~` is now expanded
  correctly on read
- [x] HMAC JWT from Agent header - if the Agent is set up with user identity at startup time, it can send that identity to Gate (via the http protocol) 
      as a header. This is primarily useful for the multi-tenant configuration
- [ ] Keychain storage — optional future  source of identity
- [ ] Certificate - optional future source of identity
- [ ] Device authorization grant (RFC 8628) — probably not necessary
- priority: low
- comment: different organizations have different ways of providing identity. Would 
  prefer to wait for feedback before trying to implement specific additional identity sources




### Task: Optionally create a Portcullis-Gate API to collect the list of DENY responses, along with trace/session information
not sure if this is necessary. It might be helpful for troubleshooting
- priority: very low
- comment: not sure if the juice is worth the squeeze


### Task: Add a login capability to Portcullis-Guard [DONE]
This would potentially prevent a particularly nasty rogue agent from knowingly creating a request that would require
escalation, waiting for the response, abusing some sort of direct HTTP mechanism to edit and approve the request, and
then trying again, without the user being aware that it was happening.
- priority: medium-low
- comment: much of this is just a port of the equivalent work we've done for 
  Portcullis-Gate login


### Task: Allow the 'edit' capability for escalation claims to be turned on and off by configuration [DONE]
This should be straightforward - the edit capability is already on a templated web page, so it should
be easy enough to remove the edit option via template rules
- priority: medium

### Task: Consider some mechanism to explain the escalation claims in human language
This might be very tricky, given how complex some MCP requests can be.
- priority: low

### Task: Configuration option to disable the Portcullis-Gate web page, thus eliminating port contention  [DONE]
- priority: medium-low
- comment: without the web interface, Portcullis-Gate can't offer oidc-login
- comment: if we offer the streamable-http version, there won't generally be port 
  contention 

### Task: Potential for limited-use of the escalation tokens at Portcullis-Gate
Configuration option at Portculils-Gate to allow escalation tokens to be used a limited number of times before being
automatically deleted
- priority: low
- comment: this might be a feature for auditors? Not sure


### Task: Add performance monitoring to Portcullis-Keep
Use the OpenTelemetry wrapper around HTTP calls to get detailed performance measurements
- priority: medium







### Task: Improve policy messaging for denials
Right now, the denial reason is fairly generic. But in the Rego reference implementation, we could include a reason as
part of the response,
potentially customized to each rule, which could then be echoed to the user.
- priority: low








### Task: consider renaming 'requires_approval' to 'escalation' in gate config Agent messaging
This is a config consistency issue - Gate has configuration that lets IT customize
the messages delivered to the User for escalation and deny results.  But instead of
calling it `escalate`, we're calling it `requires_approval`.  Which is simultaneously
more informative and less consistent.
- priority: low







### Task: Migrate all the security complaint supression (in dev mode)
The default behavior in dev mode is to generate a warning message when there
is a security violation.  Then we've added a few 'supression' flags to keep
the system from generating a particular warning.  All of these flags should
be moved to be "under" the `mode: dev` flag, so the developers who don't need
to see the flags can turn them on and off easily.  
- priority: low
- comment: this is mostly a feature of convenience




-----------------------------------------------------
# Phase 4

### Task: Allow Portcullis-Keep to add extra data to MCP server calls
if the MCP server requires a secret or some sort of certificate in order to accept MCP requests, Keep can be
modified
- priority: medium-low
- comment: this could be really tricky to implement properly, need a lot of examples first



-----------------------------------------------------

# Phase 99

These tasks seem unnecessarily complex and not worth doing

### Task: Reload Secrets at Keep and Guard
Full config reload via admin API — extend Keep's `POST /admin/reload` and add an
equivalent Guard endpoint to re-resolve all secrets (including `vault://` URIs)
without a process restart, enabling zero-downtime secret rotation
- priority: medium-low


