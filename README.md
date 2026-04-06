# PortcullisMCP

## What is it?

PortcullisMCP is a policy enforcement gateway for MCP-based AI agents. It sits between AI agents and an organization's MCP tools to enforce identity-aware policy on every tool call, so teams can adopt MCP safely without giving up control, auditability, or least-privilege access.

   - Fine-Grained Policy Control: Use Policy-as-Code to define exactly which tools an agent can use,
     on which resources, and under what conditions.
   - Human-in-the-Loop Escalation: Automatically pause sensitive operations and request human approval before
     the agent can proceed.
   - Audit & Visibility: Centrally log every tool call, decision, and identity for full compliance and troubleshooting.

## What problem does it solve?

 PortcullisMCP solves the "Autonomous Overreach" problem in AI agents.

  While the Model Context Protocol (MCP) makes it easy to connect AI agents to tools, it creates a massive security gap:
  once an agent is connected to a tool, it typically has the same level of access as the user running it. This leads to
  four specific organizational pain points:

  1. The "All-or-Nothing" Permission Gap
  Current agents are usually "all-or-nothing." If you give an agent access to a filesystem tool, it can read, write, or
  delete any file the user can.
   - The Portcullis Solution: It provides granular, resource-level control. You can define policies
     (e.g., "The agent can read from /docs but can never write to /system_config")
     without changing the tool's code.
   - Secondary benefit: The MCP tools do not have to change in any way to support this framework.

  2. Lack of Human-in-the-Loop for Sensitive Actions
  Autonomous agents are notorious for making high-stakes decisions (like deleting a database or moving funds) without a
  "check-and-balance" step.
   - The Portcullis Solution: It implements Policy-Driven Escalation. If an agent tries to perform a sensitive action,
     Portcullis automatically pauses the request and provides a mechanism for a human to review and authorize before the
     agent can proceed.

  3. The Audit and Compliance "Black Box"
  In most setups, when an agent performs an action, the logs only show that the user performed it. There is no clear
  record of why the agent did it or if it was permitted by policy.
   - The Portcullis Solution: It centralizes Decision Logging. Every tool call is intercepted,
     evaluated against policy, and logged with a unique trace ID, providing a complete audit trail
     of what the agent requested, what the policy decided, and who (if anyone) approved it.

  4. Credential and Identity Sprawl
  Managing how agents authenticate to enterprise APIs often leads to hardcoded secrets or overly permissive service
  accounts.
   - The Portcullis Solution:
     - It maps the person sitting at the keyboard to a verified Enterprise Identity that the policy
       engine can use.
     - It manages secrets securely (via Vault or environment variables), so neither the agent nor
       the user handle secrets directly

  ---

In summary: PortcullisMCP solves the problem of trusting autonomous agents in the enterprise. It moves AI from a
unmanageable security risk to a governed, auditable, and safe corporate resource.


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
  - It works with Keep and Gate to allow users to grant their Agents temporarily escalated access to
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

Imagine you have a database MCP. That MCP might have a mechanism to allow Agents to drop tables. You can use the policy
at Portcullis-Keep to govern how that drop action is used:
- If the Agent wishes to drop a temp table: the PDP returns `allow`
- If the Agent wishes to drop a normal table: the PDP returns `escalate`

When the PDP returns `escalate`, it also returns the exact set of arguments that the Agent sent along with the request.

Portcullis-Keep will bundle the `escalate` response along with those arguments, and create a "Pending JWT" back to the
Portcullis-Gate.

Portcullis-Gate will create a URL that links to Portcullis-Guard and includes information about that "Pending JWT". Gate
sends this URL to the Agent, along with instructions which tell the Agent that the user needs to approve this escalated
privilege. The Agent should (there are no guarantees with AI Agents) provide the link to the User.

Assuming the User clicks on the link, they open up a page on Portcullis-Guard that shows the arguments that the Agent
attempted to use. The user can look at the details (which MCP server, which tool, the specific arguments used by the
Agent), and then decide whether or not to temporarily grant the escalated privilege to the Agent.

Assuming the user approves the escalated privilege, Portcullis-Guard creates a signed JWT that will be trusted by the
PDP. This signed JWT (which we call an escalation-token) contains the arguments that the PDP viewed as requiring
escalation. In essence, the fact that there's a JWT signed by Guard, that only exists because the User approved it, is a
clear indication that the User has taken responsibility for a specific action by the Agent.

The user can then ask the Agent to try the action again. This time, when Portcullis-Gate sees the request, it acquires
the escalation-token from Portcullis-Guard, and adds it to the wrapper around the retry MCP request.

When Portcullis-Keep gets this second request, it passes it on to the PDP, and it also automatically passes along any
attached escalation-tokens

When the PDP receives the request, it validates the escalation-token, and if it finds one that includes claims that
properly matches the arguments that the PDP originally viewed as requiring escalation, it considers this proof that the
User approves this action. Now, the PDP returns `allow`.

When the Portcullis-Keep receives `allow`, it passes the request on to the database MCP, which can now perform the
action.

Meanwhile, the PDP has delivered the details of the `allow` decision to the decision log, which can easily be directed
to the appropriate SIEM or other system for archiving and future review.

The escalation-token expires after a configured time. And the escalation-token only grants a narrow set of privileges,
so the Agent can't exploit the this escalation-token to perform other acts. (For example, if the escalation token
specifically allows `DROP TABLE HALIBUT`, the Agent can't use the token to `DROP TABLE SALMON`)

The User can also visit the Portcullis-Gate web page to revoke any active escalation-tokens, which prevents the agent
from using it again.

Note again that the PDP creates decision logs, both for the original `escalate` request, and then another one for the
`allow`. This second decision log entry will also contain the signed JWT (unless redacted) which will demonstrate that
the User approved the request, exactly which arguments were approved, and when this occurred.

An auditor can look at the policies captured in the PDP and compare them to the decision logs to verify that the both
the Agents and Users are in compliance with corporate policy.


## Quick Start

> **Windows users:** See [docs/quickstart-windows.md](docs/quickstart-windows.md) for a step-by-step guide covering prerequisites, PATH setup, and agent configuration.

### Prerequisites

- **Go 1.24+**
- **Docker** (optional, for full demo stack)
- **Make** (standard on Linux/Mac; install via `winget install ezwinports.make` on Windows)

### Minimal (no Docker, no OPA)

This path runs Keep with the `noop` PDP, which allows all requests. Useful for understanding the flow before adding
policy enforcement.

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

Copy `config/gate-config.minimal.yaml` to `~/.portcullis/gate.yaml` and adjust paths. Gate starts automatically when the
MCP client launches.

Verify Gate is running via the management API at `http://localhost:7777`.

### Full Demo Stack (Docker)

This path runs the complete stack: OPA with a sample policy bundle, Keep, Guard, and two example MCP backends (a mock
enterprise API and a web fetch server).

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

The last request should trigger an escalation. The agent will present a link.
Click it to open the Guard approval page at `http://localhost:8444`, review the request,
and approve it. Then ask the agent to try again; it should succeed.

```sh
# Stop the demo stack
make demo-stop
```



## Configuration

### Gate (`~/.portcullis/gate.yaml`)

- `config/gate-config.minimal.yaml` â€” minimal config for local testing
- `config/gate-config.example.yaml` â€” full production config with mTLS

### Keep

- `config/keep-config.minimal.yaml` â€” minimal config; uses `noop` PDP by default
- `config/keep-config.example.yaml` â€” full production config with mTLS and OPA

### Guard

- `config/guard-config.minimal.yaml` â€” minimal config for local testing
- `config/guard-config.example.yaml` â€” full production config

### Demo stack configs

- `deploy/docker-singletenant/keep-demo.yaml` â€” Keep config for the Docker demo
- `deploy/docker-singletenant/guard-demo.yaml` â€” Guard config for the Docker demo
- `deploy/docker-singletenant/opa-config.yaml` â€” OPA config for the Docker demo

### Overriding identity in gate.yaml

When using the OS identity source (for local testing), you can override user identity fields to simulate different users
and group memberships without OIDC infrastructure:

```yaml
identity:
  strategy: "os"
  user_id: "alice@example.com"
  display_name: "Alice Developer"
  groups:
    - "developers"
    - "admin"
```

If `user_id` is not specified, it defaults to the OS username.

### Environment variables

All configs support `envvar://` syntax for environment variable expansion. Use this for secrets rather than hardcoding
them:

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

- Fast-path local rules â€” sandbox containment without network round-trips
- User identity â€” OIDC/OAuth2 or OS fallback (OS identity is for testing only)
- Escalation tokens â€” HitL-authorized operations via signed JWTs
- Pluggable PDP â€” OPA integration included; noop PDP for getting started
   - OPA provides extensive support for audit via decision logs
- Transport support â€” stdio and HTTP (Streamable HTTP, SSE) for MCP backends
- Optional TLS â€” mTLS for production, plain HTTP for development
- Bearer auth â€” shared secret authentication between Portcullis-Gate and Portcullis-Keep, Portcullis-Guard

### Roadmap

see `docs/roadmap.md`


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

See [docs/vault-integration.md](docs/vault-integration.md) for the full URI specification, examples, and administrative
prerequisites.


## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Security

To report a vulnerability, see [SECURITY.md](SECURITY.md).

There is an exotic edge case involving a desktop agent that somehow gains direct HTTP Post ability, secretly generates
escalatory requests, receives the approval URL from Portcullis-Keep, and directly visits the Portcullis-Guard to approve
the escalation without any human involvement or visibility. For production Guard deployments, see
[docs/guard-sso-proxy.md](docs/guard-sso-proxy.md) for guidance on preventing this.

## License

Apache License 2.0. See [LICENSE](LICENSE).



## Common Objections

**Portcullis-Keep is a single point of failure**
The Keep servers only hold individual requests in memory, and can (and should) be implemented in a round-robin cluster

**I don't have managed devices, so this won't work**
Even if you don't have managed devices, you can still use this mechanism to enforce security
on any MCP tool that is managed by the organization.  Yes, the user may call out to some MCP
that is out of the organization's control, but one wouldn't expect that those MCPs would have access to significant
organization resources

**The Agents can spoof the requests**
The Agent's MCP requests are wrapped in additional metadata that includes the user identity and
the communications channel is protected by bearer tokens. The Agent would have to use raw HTTP POSTS,
know the location of the Portcullis-Keep, know the user's oidc-token, and know the bearer token.

**Escalation is not secure**
Escalation is an optional feature you can control entirely through policy.
You can mandate that no tool ever escalates
if you choose. For deployments that do use escalation, Guard should be placed behind a corporate SSO proxy (Cloudflare
Access, Pomerium, nginx + oauth2-proxy, etc.) so only a human who can satisfy an interactive
SSO challenge can reach the approval page. An agent that receives the approval URL cannot
complete the SSO login and therefore cannot
self-approve. See [docs/guard-sso-proxy.md](docs/guard-sso-proxy.md) for deployment examples.

**Great, another policy language**
Portcullis is designed to use existing policy systems, it does not implement a policy engine. The
reference example uses OPA and Rego, but it can be modified to support other PDPs.

**This won't scale to the size of my organization**
The Portcullis-Keep can scale horizontally and each supports a large number of simultaneous connections. The PDPs can be
scaled horizontally as well. You can have geographically disparate Portcullis-Keep clusters anywhere you like,and the
regional Gate instances could be configured to talk to the regional Keep and Guard clusters.

**Portcullis-Guard maintains user state, so it can't scale**
You can use sticky sessions to help with this. In addition, we are already planning on adding distributed caching to
Portcullis-Guard to improve its scalability

**I can't have MCP servers in my network**
Portcullis-Keep does not care where the MCP servers are. And it doesn't send any extra information to the MCP server. So the MCPs could be external, and Portcullis becomes the single internal source that firewall-permitted to interact with the external MCPs


**I don't want to have to write custom policy for every tool**
As a reference implementation, we have created a table-based policy lookup model that should make policy setup much
easier. And this reference implementation has the ability to delegate to custom Rego logic.

**We would need helpdesk support to implement this**
PAC.Labs provides helpdesk and consulting support for PortcullisMCP, with several tiers of support available, including
24/7, if required.

**We would need mutual TLS (mTLS) between the servers**
The system supports mTLS between Portcullis-Gate and Portcullis-Keep.  Support
for Portcullis-Gate <-> Portcullis-Guard is on the roadmap.

**This will add latency to the MCP calls**
Yes, just like any other system that enforces fine-grained policy. Having said that, the additional latency is on the
order of 100 milliseconds.

**I already have MCPs deployed and I don't want to move them yet**
You aren't required to put all of your MCPs behind Portcullis. You can migrate your tools into the Portcullis security
framework over time.


**Policies will get complex**
From a compliance and security perspective, a complex-but-correct Agent MCP policy is better than a simple-but-wrong
Agent MCP policy. We have done what we can to make the policy approach as simple as possible for common use-cases.
[PAC.Labs](https://paclabs.io) can help with policy architecture and authoring, if that would be helpful.

For a deeper treatment of enterprise objections and detailed technical responses, see
[docs/enterprise-objections-responses.md](docs/enterprise-objections-responses.md).









## Frequently Asked Questions

**Will this work with our existing IdP (Okta/Azure AD/Ping)**
Yes. Gate sends an oidc-token to Keep, and Keep validates and parses it. As long as it follows the JWT model and Keep
can reach the public key for signature validation, it should work fine.

**What happens if the PDP is unavailable**
We fail closed, returning an error to the Agent and User. Portcullis-Keep never forwards an MCP Request to an MCP server
unless the PDP responds with 'allow'.

**Can an Agent exfiltrate data through an authorized tool**
Yes. We are only monitoring user access to tools, not the security of the tools themselves.

**What happens if Portcullis-Gate is unavailable**
The Agent will not be able to access any of the MCPs that are protected by Portcullis. This would typically be addressed
by restarting.

**Do my MCP tool authors need to know about Portcullis**
Portcullis should be transparent to the MCP tool implementations. Although arguably, knowing that Portcullis will be
responsible for enforcing fine-grained user-access policy should make the MCP tool author's job easier.

**Does Gate store the user's OIDC token anywhere**
You have options here. We allow configurations that pull the oidc-token from storage, and also using an OIDC login
system to fetch the credentials from the IdP and keeping them in-memory.



**If a blackhat user gets access to the OIDC token, can they abuse it?**
Assuming the token is pulled from the hard-drive: It depends on the type of token. DPoP (Demonstrating Proof of
Possession) or mTLS-bound tokens would be much less vulnerable than normal bearer tokens. Portcullis should work with a
variety of different token types.
Mitigation mechanisms would include: having the PDP (Policy Decision Point) return `escalate` for every high-privilege
call, and to protect the Guard behind an SSO Proxy.

**My MCP Servers require additional security information with each call**
We are planning on adding ways for the Portcullis-Keep to send extra information with each request, to address this
need. Having said that, if you can put the MCP servers into a private zone where they are inaccessable from the employee
network, perhaps you no longer need that capability.

**Is the policy managed by groups, roles, userids or something else**
Portcullis-Keep pulls claims from the oidc-token and sends them as part of the Principal to the policy engine. Most
common claims are already supported. You control the policy, so you can enforce on any criteria (or combination of
criteria) that you like. Other claims can be added if necessary.


**My users have several agents on their desktop, how would this work?**
Right now, Portcullis-Gate is designed to be a stdio MCP tool interface for one Agent. So you would need to have
multiple Portcullis-Gate instances running, listening on different ports for web traffic (or disabling the web page for
Portcullis-Gate altogether to eliminate the need to listen on a port).

We are planning on implementing a streamable-http interface for Portcullis-Gate, so that one gate can support multiple
agents in parallel.

**What about Telemetry?**
OpenTelemetry is embedded into all three elements of the system.

**What about monitoring**
Portcullis-Keep and Portcullis-Guard include `/healthz` and `/readyz` endpoints for monitoring.

**Users are complaining about policy denials**
When Portcullis-Keep (and the PDP) deny a request, the error message back to the user will include a `trace_id` from the
telemetry. This will be mapped from Gate to Keep to PDP and back, and should provide very detailed tracing of exactly
what path the call took, which will allow a reviewer to understand why a particular call was denied. We also include the
`trace_id` on the escalate response, although typically it is not used.

**Auditors want to know that this is capturing everything**
Every decision by OPA is logged in SIEM-friendly ways. The only thing not captured are Agent-driven reads of the
approved areas of the user's local storage. Capturing decision logs from those actions are on the roadmap.

**How do I change my policies**
If you use the OPA-based implementation, you can manage the policy like any other codebase, and build policy bundles,
which can then be deployed to the OPAs. Explaining OPA's capabilities are beyond the scope of this document, but PACLabs
has extensive experience helping organizations use Policy as Code with OPA and Rego to implement policy solutions.

**What happens if Portcullis-Keep is unavailable**
You won't be able to use any of the MCPs that are protected by the Keep. Setting up Keep in a high-availability cluster
is recommended.

**What happens if Portcullis-Guard is unavailable**
Users/Agents will be able to use the MCPs for work that is allowed by policy, but there will be no escalation path until
Guard has recovered.

**How do we rotate secrets**
Right now, you'll need to restart Keep and Guard instances to get them to load new secrets. If they're in a cluster, you
can do a rolling restart. We have a roadmap item for allowing remote reloads of the configuration on-demand, to refresh
secrets.

Gate is tied to the User and Agent, and is likely to restart frequently. In any case, adding an API to an end-user
device seems to cause more problems than it would solve.

**Can I test my policies before deploying them**
for OPA:

- OPA Control Plane systems, such as [EnforceAuth.com](https://enforceauth.com) allow for multiple environments for
  testing, and code promotion.
- The open source Raygun testing tool can be used to exercise the policy bundles against known inputs
- Finally, opa test allows policies to be tested directly

Other policy systems, such as [Permit.io](https://permit.io) have their own testing regimes, and can and should be
developed with a Policy as Code / SDLC mindset.



**What is the most secure Portcullis setup available**
- Portcullis-Gate requires interactive OIDC login (Authorization Code + PKCE).
- Gate stores short-lived oidc token in memory only
- Portcullis-Keep validates issuer/audience/expiry and enforces short TTL.
- Gate to Keep uses mTLS
- High-privilege actions still require escalation by policy
- Escalation is protected via Portcullis-Guard SSO proxy to prevent direct agent approval.


**What about users that approve escalations without looking at them closely**
Fixing alert fatigue in humans is beyond the scope of our remit. In theory, you could have a second AI Agent that looked
at the "Pending JWT" to see if the claims embedded within it seemed reasonable, and provide a warning to the User when
the request seemed suspiciously broad or dangerous. But to some degree, that would create a new compliance challenge,
instead of resolving one.


**Can we make the approval page details more user friendly?**
That's on the roadmap.  It's tricky to get right.


**Will this solution run well in a multi-region enterprise**
The workload of this solution is moderate on a per-call basis, and the major network latency in the workflow is the
Agent crunching data. We have every reason
to believe it will scale well with one central implementation.

But there's no reason it would not work well with multiple regional instances of this solution, each running in
isolation from the other. (Note: trying to have a hybrid model, with different Keep clusters but one common Guard
cluster can work, but it would require the same keys across all instances). The 'pivot' point for this is the
configuration of the Gate instance - it must be connected to the appropriate Keep/Guard instance.

This is also true for different departments, divisions, business units, etc - if they have different IdPs, different
requirements for certificate strength, etc - a different family of Gate/Keep/Guard servers can be configured for each.
The assumption here is that the user (or the user's machine) would be in one and only one of these "domains" at a time.


