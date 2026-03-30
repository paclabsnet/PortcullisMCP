# Implementation

## Portcullis-Gate
Portcullis-Gate is an MCP proxy server that typically runs locally on a user's workstation, alongside an AI agent.
You would configure the agent to launch and use it as the only MCP. Here's an example for claude desktop:

```json
{
  "mcpServers" : {
    "portcullis": {
       "command" : "/usr/local/bin/portcullis-gate",
       "args": ["--config", "/home/user/.portcullis/gate.yaml"]
    }
  }
}
```

note that Portcullis is an enterprise solution, and we're assuming that this configuration would be managed by IT.
Otherwise, a clever (but also foolish) user would potentially be able to interact with the enterprise MCPs directly.

### Responsibilties
Portcullis-Gate has four responsibilities:
1) approve/deny local filesystem reads - this is a convenience feature, for speed
2) collect OIDC tokens and escalation tokens from the user for identification purposes
3) defer all other MCP requests to Portcullis-Keep, sending the OIDC and escalation tokens along with the MCP request
(wrapping the MCP request with additional metadata, so the AI agents have no ability to 'spoof' the request)
4) optionally sending every local policy decision to the Portcullis-Keep (for accounting/audit purposes)

`gate.yaml` provides the necessary configuration to reach out to the central Portcullis-Keep for enterprise MCP
management.



## Portcullis-Keep
The keep is the centralized MCP proxy. it is responsible for evaluating MCP requests from the user's AI agents against
corporate policy. The server is stateless (every incoming MCP request is evaluated in isolation) so it can be
horizontally scaled.

The Keep must be accessible in any sort of DMZ for VPN access. However, once you have Keep in place, you can put all of
the actual MCP servers in a private space. Only the Keep should be accessing the MCPs directly. This should
significantly reduce the risk of user's AI agents going rogue with the enterprise MCPs.

The Keep will package the request and the appropriate metadata, and send that to a PDP for an authorization decision. It
will get back a response from the PDP - one of: allow, deny, escalate .

- allow: Keep will send the original MCP request on to the appropriate enterprise MCP, waits for the response from the
  MCP, and sends that response back to the appropriate Gate
- deny: Keep will respond itself to the request, and send the denial back to Gate. The enterprise MCP never sees the
  request.
- escalate: Keep will respond itself to the request. Optionally, it can create instructions for the user to follow to
  approve the escalation. There are various ways these instructions can be created, the most secure and reliable way is
  to create an `escalation_request` JWT, that is signed by Keep, and send that back to the user. In principle, Keep
  could send that JWT as part of a URL, so the user just has to click on the URL to view the JWT and use the claims
  within to create an `escalation_token` JWT (note that there are both `escalation_request` and `escalation_token` JWTs,
  and they are different. Most critically, the `escalation_request` is signed by Keep, not the the the enterprise, so in
  principle it won't be trusted by the PDP)

Keep also has an additional responsibility:
- accept decision logs from the various Gate instances, aggregate them and send them to the appropriate decision log
  receiver



## PDP
The PDP is responsible for 'vetting' every enterprise MCP request (along with metadata) against policy. How much vetting
is up to the enterprise.

The PDP has two responsibilities:
1) return allow/deny/escalate to the Keep
2) generate decision logs about the decisions it makes

### Allow
The PDP determines that the MCP request from the AI Agent is in accordance with enterprise policy.

**ALSO**

The PDP will return `allow` if the request would normally require escalation, and an appropriate `escalation_token` has
been attached to the metadata.


### Deny
The PDP determines that the MCP request from the AI Agent is not in accordance with enterprise policy, and no exception
can be made


### Escalate
The PDP determines that the MCP request from the AI Agent is not in accordance with enterprise policy, unless there is
some proof from the user (i.e. an `escalation_token`) that the user approves













