# PortcullisMCP

## What is it?

PortcullisMCP is a security gateway for MCP: it sits between AI agents and an organization's MCP tools to enforce identity-aware policy on every tool call, so teams can adopt MCP safely without giving up control, auditability, or least-privilege access.

   * Fine-Grained Policy Control: Use Policy-as-Code to define exactly which tools an agent can use,
     on which resources, and under what conditions.
   * Human-in-the-Loop Escalation: Automatically pause sensitive operations and request one-time human approval before the agent
     can proceed.
   * Audit & Visibility: Centrally log every tool call, decision, and identity for full compliance and troubleshooting.

## What problem does it solve?

 PortcullisMCP solves the "Autonomous Overreach" problem in AI agents.

  While the Model Context Protocol (MCP) makes it easy to connect AI agents to tools, it creates a massive security gap: once an agent is connected to a tool, it typically has the same level of access as the user running it. This leads to four specific organizational pain points:

  1. The "All-or-Nothing" Permission Gap
  Current agents are usually "all-or-nothing." If you give an agent access to a filesystem tool, it can read, write, or delete any file the user can.
   * The Portcullis Solution: It provides granular, resource-level control. You can define policies
     (e.g., "The agent can read from /docs but can never write to /system_config") 
     without changing the tool's code.
   * Secondary benefit: The MCP tools do not have to change in any way to support this framework.

  2. Lack of Human-in-the-Loop for Sensitive Actions
  Autonomous agents are notorious for making high-stakes decisions (like deleting a database or moving funds) without a "check-and-balance" step.
   * The Portcullis Solution: It implements Policy-Driven Escalation. If an agent tries to perform a sensitive action, Portcullis automatically pauses the request and generates a secure approval URL 
   for a human to review and authorize before the agent can proceed. 

  3. The Audit and Compliance "Black Box"
  In most setups, when an agent performs an action, the logs only show that the user performed it. There is no clear record of why the agent did it or if it was permitted by policy.
   * The Portcullis Solution: It centralizes Decision Logging. Every tool call is intercepted,   
     evaluated against policy, and logged with a unique trace ID, providing a complete audit trail 
     of what the agent requested, what the policy decided, and who (if anyone) approved it.

  4. Credential and Identity Sprawl
  Managing how agents authenticate to enterprise APIs often leads to hardcoded secrets or overly permissive service accounts.
   * The Portcullis Solution: 
     - It maps the person sitting at the keyboard to a verified Enterprise Identity that the policy 
       engine can use. 
     - It manages secrets securely (via Vault or environment variables), so neither the agent nor 
       the user handle secrets directly

  ---

  In summary: PortcullisMCP solves the problem of trusting autonomous agents in the enterprise. It moves AI from a unmanageable security risk to a governed, auditable, and safe corporate resource.


## How does it work?

Portcullis is a system with three parts:
- Portcullis-Keep: the central MCP Gateway Proxy.  It is the secure checkpoint between every Agent
  and every MCP tool server.
  - It validates the identity of each user as their Agents consume MCP tools
  - It enforces organization policy on every tool request, using a Policy Decision Point to evaluate 
    the request in detail
  - It hides the individual MCP instances behind a common, consistent call framework

- Portcullis-Gate : the edge interface
  - Mounted on individual machines alongside Agent desktops.
  - It acts as the single interface to all enterprise MCP tools
  - It provides a local filesystem MCP, enforcing organizational policy for reads and writes
  - It securely provides user credentials to the Keep

- Portcullis-Guard: the 'escalation' service
  - It works with Keep and Gate to allow users to give their Agents temporarily escalated access to 
    MCP tools


### Architecture

For a detailed breakdown of components and communication flows, see [ARCHITECTURE.md](./ARCHITECTURE.md).

```
Agent <--> portcullis-gate <--> portcullis-keep <--> PDP (OPA or custom)
                          |                    |
                          |                    +--> streaming-http, sse & stdio MCP Backends
                          |                         (APIs, databases, enterprise services)
                          |
                          +--> Local Filesystem (fast-path, no network)
```


### Explain 'escalation'

Imagine you have a database MCP.  That MCP might have a mechanism to allow Agents to drop tables. You can use the policy at Portcullis-Keep to govern how that drop action is used:
- If the Agent wishes to drop a temp table: the PDP returns "allow"
- If the Agent wishes to drop a normal table: the PDP returns "escalate"

When the PDP returns "escalate", it also returns the exact set of arguments that the Agent sent along with the request.

Portcullis-Keep will bundle the escalate response along with those arguments, and create a "Pending JWT" back to the Portcullis-Gate.

Portcullis-Gate will create a URL that allows the user to view the arguments and optionally approve the request.  Gate sends this URL to the Agent, along with instructions which tell the Agent that the user needs to approve this escalated privilege.  The Agent should (there are no guarantees with AI Agents) provide the link to the User.

Assuming the User clicks on the link, they open up a page on Portcullis-Guard that shows the arguments that the Agent attempted to use.  The user can look at the arguments, and then decide
whether or not to approve the escalated privilege.

Assuming the user approves the escalated privilege, Portcullis-Guard creates a signed JWT that is trusted by the PDP. This signed JWT (which we call an escalation token) contains the arguments that the PDP viewed as requiring escalation.

The user can then ask the Agent to try the action again.  This time, when Portcullis-Gate sees the request, it can acquire the escalation token from Portcullis-Guard, and add it to the wrapper around the MCP request that comes from the agent.

When Portcullis-Keep gets this second request, it passes it on to the PDP, but it also automatically passes along any attached escalation tokens

When the PDP receives the request, it validates the escalation token, and if it finds one that includes claims that properly matches the arguments that the PDP originally viewed as requiring escalation, it considers this proof that the User approves this action. Now, the PDP returns "allow".

When the Portcullis-Keep receives "allow", it passes the request on to the database MCP, which can now perform the action.

The escalation token expires after an IT-configured time.  And the escalation token only grants a narrow set of privileges, so the Agent couldn't abuse the existence of this escalation token to perform other acts.  (For example, if the escalation token specifically allows `DROP TABLE HALIBUT`, it couldn't use the token to, say `DROP TABLE SALMON`)

The User can also visit the Portcullis-Gate web page to delete any active escalation tokens, which prevents the agent from taking advantage of it again.

Note that the PDP will create decision logs, both for the original 'escalate' request, and then another one for the 'allow'.  And the second decision log will contain the JWT (unless redacted) which will show that the user approved the request, and exactly which arguments were approved.



## Quick Start

> **Windows users:** See [docs/quickstart-windows.md](docs/quickstart-windows.md) for a step-by-step guide covering prerequisites, PATH setup, and agent configuration.

### Prerequisites

- **Go 1.24+**
- **Docker** (optional, for full demo stack)
- **Make** (standard on Linux/Mac; install via `winget install ezwinports.make` on Windows)

### Minimal (no Docker, no OPA)

This path runs Keep with the `noop` PDP, which allows all requests. Useful for understanding the flow before adding policy enforcement.

```sh
# Build and install
make build && make install

# Run Keep with the minimal config (noop PDP, no OPA required)
make run-keep
```

Then configure your MCP client to launch Gate. Example for Claude Desktop (`claude_desktop_config.json`):

```json
"mcpServers": {
    "portcullis": {
        "command": "portcullis-gate",
        "args": ["-config", "~/.portcullis/gate.yaml"]
    }
}
```

Copy `config/gate-config.minimal.yaml` to `~/.portcullis/gate.yaml` and adjust paths. Gate starts automatically when the MCP client launches.

Verify Gate is running via the management API at `http://localhost:7777`.

### Full Demo Stack (Docker)

This path runs the complete stack: OPA with a sample policy bundle, Keep, Guard, and two example MCP backends (a mock enterprise API and a web fetch server).

**Prerequisites:** Go 1.24+, Docker

```sh
make build && make install && make demo-start
```

Services started:
- Keep on `http://localhost:8080`
- Guard on `http://localhost:8444`
- OPA on `http://localhost:8181`
- Mock enterprise API and fetch-mcp (internal to Docker network)

Configure Gate as above, then try these prompts with your agent:

```
What services are available from Portcullis MCP?

Please use Portcullis to fetch the latest headlines from bbc.com

Please use Portcullis to query orders for customer C001

Please use Portcullis to update order O001 status to shipped
```

The last request should trigger an escalation. The agent will present a link — click it to open the Guard approval page at `http://localhost:8444`, review the request, and approve it. Then ask the agent to try again; it should succeed.

```sh
# Stop the demo stack
make demo-stop
```



# Configuration

### Gate (`~/.portcullis/gate.yaml`)

- `config/gate-config.minimal.yaml` — minimal config for local testing
- `config/gate-config.example.yaml` — full production config with mTLS

### Keep

- `config/keep-config.minimal.yaml` — minimal config; uses `noop` PDP by default
- `config/keep-config.example.yaml` — full production config with mTLS and OPA

### Guard

- `config/guard-config.minimal.yaml` — minimal config for local testing
- `config/guard-config.example.yaml` — full production config

### Demo stack configs

- `deploy/docker-sandbox/keep-demo.yaml` — Keep config for the Docker demo
- `deploy/docker-sandbox/guard-demo.yaml` — Guard config for the Docker demo
- `deploy/docker-sandbox/opa-config.yaml` — OPA config for the Docker demo

### Overriding identity in gate.yaml

When using the OS identity source (for local testing), you can override user identity fields to simulate different users and group memberships without OIDC infrastructure:

```yaml
identity:
  source: "os"
  user_id: "alice@example.com"
  display_name: "Alice Developer"
  groups:
    - "developers"
    - "admin"
```

If `user_id` is not specified, it defaults to the OS username.

### Environment variables

All configs support `envvar://` syntax for environment variable expansion. Use this for secrets rather than hardcoding them:

```yaml
backends:
  github:
    type: "stdio"
    command: "npx"
    args: ["-y", "@modelcontextprotocol/server-github"]
    env:
      GITHUB_TOKEN: "envvar://GITHUB_TOKEN"
```

### Secrets

All configs also support `filevar://` and `vault://` to reference external information in a secure
way. See **Vault Secret URI Configuration** section below for more details 



## Policy

The included policy in `policies/` provides a working starting point:

- Allows filesystem reads within the sandbox
- Requires escalation for writes to certain directories
- Denies access to protected paths (`.git`, `.portcullis`)
- Allows access to some mock enterprise API tools, denies or escalates others based on group membership
- Allows access to some websites via fetch, denies or escalates others

See `docs/policy/opa-examples.md` for detailed policy examples and testing guidance.

## Features

- Fast-path local rules — sandbox containment without network round-trips
- User identity — OIDC/OAuth2 or OS fallback (OS identity is for testing only)
- Escalation tokens — HitL-authorized operations via signed JWTs
- Pluggable PDP — OPA integration included; noop PDP for getting started
   - OPA provides extensive support for audit via decision logs
- Transport support — stdio and HTTP (Streamable HTTP, SSE) for MCP backends
- Optional TLS — mTLS for production, plain HTTP for development
- Bearer auth — shared secret authentication between Portcullis-Gate and Portcullis-Keep, Portcullis-Guard

### Roadmap
- Distributed Caching at Portcullis-Guard
- additional credentials when Portcullis-Keep interacts with MCP Servers
- Organization Workflows (such as ServiceNow)
- Additional vaults (AWS, Azure and GCP)


## Testing

```sh
go test ./...
```

## Portcullis-Gate Error Handling

The Gate is the MCP client that (typically) lives on the user's desktop along with their Agent.

This represents the "front-end" to the Portcullis system. That creates some unusual requirements
for Gate:
1) Regardless of other MCPs that are made available through the Gate MCP proxy, Gate always
   offers one specific MCP tool: `portcullis_status` 
  - `portcullis_status` allows the user and the Agent to check on the status of Portcullis-Gate
  - when the Gate is running properly, `portcullis_status` will respond with the status of
    the Gate itself, as well as a health status report from Portcullis-Keep and Portcullis-Guard
2) If Gate's configuration files are mis-configured, or there is a network issue accessing the 
   rest of the system, Gate doesn't shut down. Instead, Gate transitions to "Degraded Mode"
   - Degraded Mode changes the output of `portcullis_status`
     - when queried, it will return a description of the error that Gate is experiencing 
       (misconfiguration, network access problems, incorrect keys, etc)
     - this allows the user to reach out to IT support to help resolve the issue
     - If we don't offer degraded mode, and just shut down Gate when there's a misconfiguration, the
       user will be hard-pressed to know what is wrong.  So this represents a UX improvement
       when an outage occurs






## Vault Secret URI Configuration

See [docs/vault-integration.md](docs/vault-integration.md) for the full URI specification, examples, and administrative prerequisites.


## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Security

To report a vulnerability, see [SECURITY.md](SECURITY.md).

## License

Apache License 2.0. See [LICENSE](LICENSE).



## Common Objections

**Portcullis-Keep is a single point of failure**
The Keep servers only hold individual requests in memory, and can (and should) be implemented in a round-robin cluster

**I don't have managed devices, so this won't work**
Even if you don't have managed devices, you can still use this mechanism to enforce security
on any MCP tool that is managed by the organization.  Yes, the user may call out to some MCP
that is out of the organization's control, but one wouldn't expect that those MCPs would have access to significant organization resources

**The Agents can spoof the requests**
The Agent's MCP requests are wrapped in additional metadata that includes the user identity and
the communications channel is protected by bearer tokens. The Agent would have to use raw HTTP POSTS,
know the location of the Portcullis-Keep, know the user's oidc-token, and know the bearer token. 

**Escalation is not secure**
Escalation is an optional feature that you can control through policy. You don't have to allow
escalation, it's a policy outcome that you can mandate

**Great, another policy language**
Portcullis is designed to use existing policy systems, it does not implement a policy engine. The
reference example uses OPA and Rego, but it can be modified to support other PDPs.

**This won't scale to the size of my organization**
The Portcullis-Keep can scale horizontally and each supports a large number of simultaneous connections. The PDPs can be scaled horizontally as well.  You can have geographically disparate Portcullis-Keep clusters anywhere you like,and the regional Gate instances could be configured to talk to the regional Keep and Guard clusters.

**Portcullis-Guard maintains user state, so it can't scale**
You can use sticky sessions to help with this.  In addition, we are already planning on adding distributed caching to Portcullis-Guard to improve its scalability

**I can't have MCP servers in my network**
Portcullis-Keep does not care where the MCP servers are. And it doesn't send any extra information to the MCP server.

**My MCP Servers require additional security information with each call**
We are planning on adding ways for the Portcullis-Keep to send extra information with each request, to address this need.  Having said that, if you can put the MCP servers into a private zone where they are inaccessable from the employee network, perhaps you no longer need that capability.

**Is the policy managed by groups, roles, userids or something else**
Portcullis-Keep pulls claims from the oidc-token and sends them as part of the Principal to the policy engine. Most common claims are already supported. You control the policy, so you can enforce on any criteria (or combination of criteria) that you like. Other claims can be added if necessary.

**I don't want to have to write custom policy for every tool**
As a reference implementation, we have created a table-based policy lookup model that should make policy setup much easier. And this reference implementation has the ability to delegate to custom Rego logic.

**I would need helpdesk support to implement this**
PAC.Labs provides helpdesk and consulting support for PortcullisMCP, with several tiers of support available, including 24/7, if required.

**My users have several agents on their desktop, how would this work?**
Right now, Portcullis-Gate is designed to be a stdio MCP tool interface for one Agent. So you would need to have multiple Portcullis-Gate instances running, listening on different ports for web traffic.   

We are planning on implementing a streamable-http interface for Portcullis-Gate, so that one gate can support multiple agents in parallel.

**What about Telemetry?**
OpenTelemetry is embedded into all three elements of the system.  

**What about monitoring**
Portcullis-Keep includes `/healthz` and `/readyz` endpoints for monitoring

**Users are complaining about policy denials**
When we deny a request, the error message back to the user will include a `trace_id` from the telemetry. This will be mapped from Gate to Keep to PDP and back, and should provide very detailed tracing of exactly why a particular call was denied.  We also include the `trace_id` on the escalate response, although typically it is not used.

**Auditors want to know that this is capturing everything**
Every decision by OPA is logged in SIEM-friendly ways

**How do I change my policies**
If you use the OPA-based implementation, you can manage the policy like any other codebase, and build policy bundles, which can then be deployed to the OPAs.   Explaining OPA's capabilities are beyond the scope of this document, but PACLabs has extensive experience helping organizations use Policy as Code with OPA and Rego to implement policy solutions.








