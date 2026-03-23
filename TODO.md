# Phase 2

## Tasks



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

### Task: Acquire Human Credentials (at Gate)
- Modify Gate to support a local token store
- what about adding credentials to a keychain instead of a local file, and Gate pulls from the keychain? 
  - Perhaps an option.
- Device authorization grant  (see below in Implementation Details)
- priority: medium-high

### Task: Improve JWT security at the PDP
- the PDP should not only verify that the JWTs are valid, but it should also only accept JWTs where the UserID from the Principal matches the Subject embedded in the JWT
(owner: @johndbro1)
note - this is for the individual escalation JWTs.  Part of the validation process
- priority: medium

### Task: Fail closed for Gate if Keep is unavailable
- this is not super important, since if Keep is down, no non-local MCP requests can occur
- Basically, ensure that Gate indicates to the user that the Portcullis server is not available right now, try again later.
- low priority

### Task: at the PDP, Get rid of RequestId, use TraceID instead
- this allows the trace to be included in the deny message
(owner: @johndbro1)
- low priority

### Task: Optionally Include the traceid in the Deny, Escalate and Workflow messages back to the user
- purpose: allows a user to escalate to the enterprise security team if they aren't allowed to do something they think they should be able to
- low priority

### Task: Optionally create a Gate API to collect the list of DENY responses, along with trace/session information
- not sure if this is necessary. It might be helpful for troubleshooting
- very low priority

### Task: Tabular -> Custom failover
- instead of Tabular and Custom being equivalent, perhaps we just use custom when the tabular rules don't come up with an answer
- basically
```
decision := custom.decision if {
   decision == undefined
}
```

An interesting idea if it works. Will need to update the Rego to test.
(owner: @johndbro1)

This could be useful as a way to implement the 'workflow' option as an example

priority: medium


### Task: Update the implementation of the 'input eval ladder' 
In rego, there's a better way to run an input through a variety of tests to see if one passes.
- documented in policy_todo.txt

priority: medium


### Task: In addition to allow / deny / escalate , add workflow
This will handle the scenario where the *user* is not authorized to do something (escalate is used when the *user*
is authorized, but the *agent* is not)

The big problem - we shouldn't do this automatically.  We should give the user the opportunity to make the request to the workflow system, asking for the additional privileges/authority.   

Ideally: at Keep, we call the workflow provider, which returns some sort of URL we can send to Gate.  Gate can display this URL to the user, to give the User the chance to request the additional privileges/authority.  

- priority: low (for now)

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

When the PDP responds with 'workflow', this means to invoke ServiceNow or some other tool to make the
necessary approvals.

Need more research:
- does Keep send the same JWT to the workflow tool?  Or does it send the key elements of the JSON, and let
  the workflow tool handle the details? Or is this something that is an implementation detail of the appropriate
  workflow provider (YES)
- it seems more secure to send a JWT, because that way there's evidence that the request was created properly
  by the system flow.  But on the other hand, this requires the workflow tool to be able to process and 
  validate JWTs
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


