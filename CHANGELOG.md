## [0.5.2]

### Added

- Multi-tenant escalation support: Gate can operate in single-tenant (individual user) or multi-tenant (AI-enabled console) mode, with escalation scoped per-session or per-fingerprint
- Redis-backed pending and token stores for multi-tenant deployments, with context-partitioned keys
- Lazy Claim pattern: escalation tokens are claimed synchronously on agent retry rather than via background polling
- Parallel escalation rulesets: the `escalate` field in policy data is now an array, allowing multiple independent escalation paths per tool (e.g., clerk path and developer path)
- Atlassian Rovo MCP integration tested and documented
- Demo stack updated to support multiple concurrent users with per-user escalation flows
- `disable_customer` tool added to mock enterprise API with custom policy (admin=allow, non-admin=workflow)

### Fixed

- Gate: consistent relative path resolution and symlink containment for local filesystem tools
- Gate: recursive localfs tools are now kept out of forbidden directories
- Gate: multi-tenant session IDs are persisted and fingerprint is enforced across reconnects
- Gate: on Windows, prevent double-launch of Gate instances by the MCP client
- Keep: alias guard now rejects requests using the real name of an aliased tool
- Keep: identity sources that cannot be verified are rejected in strict verify modes
- Keep: hardened error handling for identity and alias edge cases

## [ 0.4.2]

### Added

- Portcullis-Guard now supports oidc-login (optional) if you want to ensure that only humans are approving escalations
- Portcullis-Keep now supports injecting the user identity token it gets from Portcullis-Gate into the headers or arguments of the calls to the destination MCP server .  So you don't have to deal with long-lived tokens on the filesystem. 
- Portcullis-Keep supports an identity-exchange webhook call - if the user identity token is not appropriate for the MCP destination, you can configure Keep to call a webhook with the token, and get back a JSON structure or string that matches your desired format. This will be injected just like the tokens above.  This has not been tested yet.

### Fixed
- make demo-start now always regenerates .env with the current version


### Upcoming
- testing of the identity injection webhook
- testing of the identity normalization webhook



## [0.4.1]

### Added

- Initial release
- support both stdio and mcp-based Portcullis-Gate
- support Gate both in a single-tenant (i.e. individual user) mode as well as a multi-tenant mode for AI-enabled consoles
- Supports Portcullis-Guard to allow users to authorize the Agent's use of MCP capabilities
- Portcullis-Keep hides the MCPs behind a common, central proxy, which handles authentication, authorization and other chores, so the MCPs can focus on their business logic


