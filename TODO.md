# TODO List


### Item: Allow "public-facing" Portcullis Gate

Up until this point, we've thought about Portcullis as being an internal tool for
internal developers. But there's another use-case: an organization is providing an Agent to assist customers and potential customers. And in order to do its job properly, that Agent will need to access APIs within the organization's control.

We can then see a scenario where people are interacting with the agent via a website,
and the agent is performing various API calls on that person's behalf. Obviously, it is better from a security, consistency and tracking perspective if that Agent interacts with an MCP instead of a naked API.  And if the Agent is interacting
with an MCP, that MCP could now be proteced by Portcullis.

#### Implications

1. Portcullis-Gate will need to support streamable-http
   The agent will be interacting with many customers in parallel. It will need to:
   - listen on a well-known port for incoming MCP requests
   - properly support multiple MCP requests in parallel
   - build and tear-down sessions cleanly and properly
2. Portcullis-Gate will need to support multiple simultaneous users
   Right now, Gate is built around the assumption of just one user. But that's
   not going to work for a public-facing Agent. We need to make sure that MCP calls for Customer X are distinguishable from MCP calls for Customer Y.
   - the Agent must provide an oidc-token on behalf of the customer.  How the Agent
     acquires this token is beyond the scope of Portcullis
   - Portcullis-Gate will include the token in the EnrichedMCPRequest
   - Portcullis-Keep will validate the token
   - the MCP tool API will probably expect customer identification information in the 
     MCPRequest itself. It might even be this same oidc-token. That's up to the author.
3. **No-Escalation Option** In the public-facing scenario, the idea of letting a 
   customer choose to approve an escalation seems very risky. It seems reasonable to allow the IT admins the ability to turn off escalation as an option.
   - This can be done today by not configuring the Portcullis-Guard
   - It might also be preferable to have a configuration setting that simply disables 
     escalation, so even if Portcullis-Guard configuration was added to the YAML, it would still treat `escalate` as `deny`
4. **No-Escalation Tracking** It might be UX-friendly to log these escalation 
   responses in a thoughtful way so that IT could identify that access to certain tools and capabilities were desired by a customer. This might be covered by existing SIEM, but it might be helpful to capture this explicitely
5. A Gate instance that is supporting multiple 
   independent agents in parallel is a server. It needs `/healthz` and `/readyz` endpoints that can be monitored.
6. If the organization wants HA on the Gate server, it will need to either turn on 
   sticky sessions at the ingress, or use a distributed cache (such as Redis)
7. We'll need a new config key:  `tenancy: single | multi` which will then create several 
   validation implications:
   - for `multi`:
     - `server.endpoints.mcp.listen` must be valid
     - `responsibility.tools.portcullis-localfs.enabled` must be false
     - `responsibility.escalation.enabled` must be false
     - `server.endpoints.management_ui` must not exist
     - `peers.guard` must not exist     - 

8. The `mcp` listener configuration will include information about the expected user token:
```
server:
  endpoints:
    mcp:
      listen: "http://localhost:8080"
      auth:
        type: "none" | "oidc-token"
        credentials:
          header: X-User-Token
```
   Gate is just passing this on to Keep to validate, so we don't have to specify details here, unless it turns out to be so difficult to debug that having an earlier set of checks is useful and not a distraction

   You might wonder why `auth.type: none` is an option. For testing!

9. Update the responsibility config tree:

```
responsibility:
  tools:
    portcullis-localfs:
      enabled: true | false
      workspace:
         <workspace config>
      forbidden:
         <forbidden config>
```

   in other words, workspace and forbidden will need to be moved

10. We'll need to implement `storage` config, in the same style as Portcullis-Guard
  - this will allow the MCP streaming sessions to be stored 
  - allows for a cluster of stateless Portcullis-Gate instances that use Redis
```
operations:
  storage:
    backend: "memory"
    # For HA deployments, use redis:
    # backend: "redis"
    # config:
    #   addr: "redis.internal:6379"
    #   password: "envvar://REDIS_PASSWORD"
    #   key_prefix: "portcullis:guard:"
```

11. default YAML config:
 - `responsibility.tools.portcullis-localfs.enabled` is true by default
 - `responsibility.escalation.enabled` is true by default
 

12. `/healthz` and `/readyz` are under the mcp listener
    - they do not require bearer tokens, even if one is specified for the mcp listener

13. `server.endpoints.mcp.auth.credentials.bearer_token` must be added to the AllowSecretsList

14. If `responsibility.escalation.enabled` is true, `peers.guard` must exist


#### Ideas







#### Decisions

1. If the config includes the `mcp` endpoint, `stdio` is automatically disabled. 
   - But if the config does not include the `mcp` endpoint, `stdio` is automatically enabled
2. If the `mcp` endpoint is configured, the `management_ui` endpoint is forbidden, otherwise it is optional
3. The marker item for SIEM logging for no-escalation tracking will be configured in the YAML



