# Phase 3

Some of these tasks were deferred from Phase 2 because they are complicated and involve access to potentially expensive
cloud resources

### Task: Static Tool List - modify Keep configuration to allow admins to load the tool list for a remote MCP into a config file, rather than querying the MCP at startup

#### Problem:
For a lot of third-party MCPs, the tool/list is gated behind OAuth. So Keep can't get the tool/list at startup.


#### Proposed Solution

For single-tenant mode, we can load the tool list from some sort of config file at Keep, and pass that list back to Portcullis-Gate

#### Implementation

Update the `mcp_backend` structure to include a new element:

```
    tool_list:
      source:  file | remote
      file: <path> 
```     

If the tool list acquisition is static, we would expect details about the file that contains the JSON that represents the tool list.  We would expect that this JSON would be the equivalent of fetching the tool list from an MCP and saving that JSON as a file. (although we don't necessarily need fields that don't provide useful information about the actual tool list)

#### Backwards compatibility

If the tool_list section is not included, the default is remote.


#### Security

- We'll assume that if the mcp_backend is listed, it is available for use. adding an extra tier of authorization for the tool list seems unnecessary.


#### Priority
- priority: high



### Task: Allow Gate to act as a Proxy for third-party MCPs that shouldn't be unified within the Portcullis MCP

#### Problem

But many MCPs require OAuth before they will return the tool list.  Keep cannot get the OAuth credentials necessary to fetch this tool list at startup, so we
can't dynamically offer the tool as part of the portcullis "family"

#### Proposed Solution

For single-tenant: the static tool list described above, so the tool becomes part of the portcullis MCP "umbrella".

For multi-tenant: Set up the Portcullis-Gate with unique endpoints for each remote MCP.  Set up the Agents to use the Portcullis-Gate endpoint as a proxy for the remote MCP. 


#### Implementation

For each remote MCP that Portcullis will proxy:
- the agents are configured with the address of Gate, with an appropriate URL endpoint that is unique for the remote MCP
- Gate passes the request onto Keep. For tool calls, it will use the current endpoint.  For tool list calls, it will use a new endpoint.  `/tool-list`

Using Figma as an example:

* Keep admins add Figma as a `bridged` MCP, specifying a local endpoint `/figma` and the actual remote URL for Figma
* Keep policy writers discover and create policy rules for Figma
* Agents are configured to use an MCP for Figma, that uses the Gate URL, but with a Figma-specific endpoint `/figma` (instead of just using `/mcp`)
* Agents start up. It will want to query the Figma MCP for the tool list 
  * Agent sends that tool list request to the Gate-managed endpoint `/figma`
  * If Gate is configured to demand authentication, it may respond with a login requirement.
  * Once the tool list request is acceptable, Gate will pass it along to the `/tool-list` endpoint at Keep
  * Keep passes that tool list request along to the true Figma MCP
  * Figma responds with headers requiring login
  * Keep passes the response (with the headers) back to Gate, which passes it back to the Agent
  * The Agent gets the user to authenticate, and repeats the tool list request
  * Gate receives the tool list request, enriches and passes to Keep as before. But now there are new headers that satisfy Figma's OAuth requirement
  * Keep evaluates and passes that tool list request along to the true Figma MCP
  * Figma validates the OAuth headers, and answers with the appropriate tool list
  * Keep sends the tool list back to Gate
  * Gate sends the tool list back to the Agent
  * Agent now has the tool list for doing stuff with Figma. All of the tool calls will go through Gate and Keep, and Keep will be able to perform authorization on the calls.
  * Agent calls for a specific tool at Figma. They will use the MCP proxy at Gate at the `/figma` endpoint
  * Gate will detect that this is a tool call, not a tool list call, enrich the request and pass it along to the "classic" tool call endpoint at Keep
    * At this point, this call to Figma is indistiguishable from any other "normal" MCP call


#### Key implementation questions and thoughts

1. When the agents use this method, Gate and Keep needs to pass headers on to Figma, and Keep and Gate need to accept the response headers from Figma and faithfully send them back to the Agent
2. Keep will require the admins to create policy rules for the individual MCP tools offered by the remote MCP (since they fail by default)
3. Each `mcp_backend` entry in the Keep config needs to support a new sub-structure:
```
   bridge:
     enabled: true | false
     endpoint: <string>     
```

  The endpoint string is expected to be short and closely aligned with the 
  name of the destination MCP

  This represents endpoints that are implemented in a bridged way, where
  Portcullis does not unify them into the portcullis MCP, but still provides
  a mechanism for authorization and decision logging.  The Users (or IT admins) will will need
  to add the MCP to the Agents, but these `bridged` MCPs will be configured to use the URL for the MCP-specific endpoint at Gate instead of the actual MCP endpoint.  Note that this `bridged` capability only applies in multi-tenant Portcullis, since single-tenant uses stdio and doesn't listen on a port for MCP requests.



4. When Gate starts up, it already fetches the list of backends.  In single-tenant mode it will be modified to ignore the ones that are `bridged`.  In multi-tenant, it will add an endpoint listener for each enabled `bridged` endpoint. There will be two types of requests that come in:
   * Tool calls
   * Tool lists
5. When requests come in to a `bridged` endpoint, Gate will:
   * wrap tool call requests in an enriched request, as done today and send
     them to Keep as done today.
   * wrap tool list requests in a different enriched request, and send it to
     a different endpoint at Keep
   * Keep will send the request on to the *actual* endpoint
   * Keep will receive the response (including the headers) from the endpoint   
     and pass it back to Gate, which will pass it back to the agent

    

#### Interesting challenges

* Backwards compatibility - the new stuff is optional, and if it isn't there,
  we assume there's no bridge
* If the destination MCP requires OAuth, we'll end up sending two different
  OAuth credentials with each request, one for Portcullis, and one for the 
  destination MCP.
* The agents will include MCP-specific auth credentials in the headers of the MCP requests (both tool calls and tool list calls). We need to make sure that we pass all of the headers from the Agent to the destination MCP, and we also need to make sure to pass all of the headers from the destination MCP back to the Agent.
  * IMPORTANT: we also need to make sure that the existing tool call flow properly handles all of the headers in both directions


#### Fail Closed

* If there is no tool call policy for a given MCP tool, we don't forward the request


#### Open Questions


#### Goals

1. Set up a policy such that a tool works, but certain specific arguments cause a deny (so, for example, you can delete something temporary, but you can't delete something important).


#### Priority
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


