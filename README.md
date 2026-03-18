# PortcullisMCP

**Enterprise MCP (Model Context Protocol) Policy Gateway**

PortcullisMCP is a policy enforcement gateway for AI agents. It sits between AI agents (Claude, Copilot, etc.) and MCP servers, enforcing enterprise access policies through an external Policy Decision Point (PDP).

## Architecture

```
Agent (Claude) <--> portcullis-gate <--> portcullis-keep <--> PDP (OPA)
     |                     |                    |
     |                     |                    +--> HTTP MCP Backends
     |                     |                    |    (APIs, DBs, enterprise services)
     |                     |                    |
     |                     |                    +--> Workflow (escalations)
     |                     |
     |                     +--> Local Filesystem (fast-path, no network)
```

- **portcullis-gate**: Local sidecar on the user's machine. Handles local filesystem access via fast-path rules and forwards requests requiring policy enforcement to Keep.
- **portcullis-keep**: Central policy enforcement service. Calls the PDP and routes to HTTP MCP backends (enterprise APIs, databases, etc.).
- **PDP (OPA)**: Policy Decision Point that evaluates requests against enterprise policy rules.
- **MCP Backends**: Enterprise services exposed via HTTP/SSE transport (not stdio, which is development-only).

## Quick Start (Local POC)

### Prerequisites
- Go 1.24+
- Docker (for OPA)
- An HTTP MCP server for testing (see below)

### Architecture Note

**Local vs. Enterprise Resources:**
- **Gate** handles local filesystem access directly (fast-path, no network overhead)
- **Keep** routes to enterprise HTTP MCP backends (APIs, databases, services that need policy enforcement)
- **Guard** provides a mechanism for user escalation, granting rights to the agents to perform actions on the user's behalf

This separation ensures:
- Fast local operations (reads in sandbox)
- Policy-enforced enterprise access (writes, APIs, databases)
- Realistic enterprise architecture (no stdio in production)


### 1. Build the binaries

```
make build & make install
```


### 2. Start OPA, Portcullis (Guard/Keep) and the Fetch & Mock Enterprise MCPs

```
docker compose up --build
```

This starts OPA on `http://localhost:8181` with the policy bundle found in the `policies/rego` directory.

It starts Portcullis Keep on port 8080

It starts Portcullis Guard on 8444

It starts Mock Enterprise API on an arbitrary port

It starts Fetch on an arbitrary port



### 3. Test it

#### Step 1 - configure Claude Desktop / Goose / Whatever uses MCPs to be aware of Portcullis

Provide the Agent with the location of the binary and the `--config` argument for the location of the
`gate.yaml` file for configuration.

The Gate exposes an MCP server on stdio. It should start automatically once the Agent knows about it.

#### Step 2 - Restart Agent

The agent should be able to find portcullis if you ask, and it should be able to enumerate the functionality.

You can verify that Gate is running by using the management API at `http://localhost:7777`.

#### Step 3 - Actual tests

"Please use portcullis to fetch the latest news from 'website'"

"Please use portcullis to query orders for customer *random number*"

"Please use portcullis to update the name of customer *random number* to Arbitrary Name"

**this last one should cause an escalation event, which should come back to you in the form of a link**

click the link to approve the request and get a JWT. Use the Gate web interface (port 7777 on localhost) to paste in the JWT.

Now ask the agent to update the name again. This time, it should work.

**Testing the flow:**
- Local filesystem reads (Gate fast-path) - never reach Keep
- Enterprise API calls (mock-enterprise-api backend) - routed through Keep → OPA → Mock server
- Policy denies/escalations are visible in Keep logs
- Check OPA decisions: `curl http://localhost:8181/v1/data/portcullis/decision -d @test-request.json`

## Configuration

### Minimal (for local testing)
- `config/gate-config.minimal.yaml` - Local testing without TLS
- `config/keep-config.minimal.yaml` - Local testing without TLS

**Testing Group-Based Policies:**
When using OS identity source (for local testing), you can override user identity fields:
```yaml
identity:
  source: "os"
  user_id: "alice@example.com"      # Override OS username
  display_name: "Alice Developer"   # Override display name
  groups:
    - "developers"
    - "admin"
```
This allows testing different user scenarios and group-based OPA policies without OIDC infrastructure. If `user_id` is not specified, it defaults to the OS username.

### Full (for production)
- `config/gate-config.example.yaml` - Full configuration with mTLS
- `config/keep-config.example.yaml` - Full configuration with mTLS and all features

### Environment Variables

Both configs support environment variable expansion using `${VAR}` syntax:

```yaml
backends:
  github:
    type: "stdio"
    command: "npx"
    args: ["-y", "@modelcontextprotocol/server-github"]
    env:
      GITHUB_TOKEN: "${GITHUB_TOKEN}"
```

## Policy Examples

See `docs/opa-examples.md` for detailed policy examples and testing guidance.

The included `policies/tabular/decision.rego` provides a minimal policy that:
- Allows filesystem reads in the sandbox
- Requires escalation for writes to certain directories
- Denies access to protected paths (.git, .portcullis)
- allows access to some of the mock enterprise APIs, but not others (without appropriate group access)
- allows access to websites via fetch, with some that are denied and some that require escalation

## Features

✅ **Fast-path local rules** - Sandbox containment without network round-trips  
✅ **User identity** - OIDC/OAuth2 or OS fallback  
✅ **Escalation tokens** - Pre-authorized operations via JWTs  
✅ **PDP integration** - OPA policy enforcement  
✅ **Workflow integration** - ServiceNow, webhooks for approvals  
✅ **Audit logging** - Batched decision logs to SIEM  
✅ **Transport support** - stdio and HTTP (SSE) for MCP backends  
✅ **Optional TLS** - mTLS for production, HTTP for development  
✅ **Bearer auth** - Defense-in-depth authentication  

## Documentation

- [CLAUDE.md](CLAUDE.md) - Full architecture and design document
- [docs/opa-examples.md](docs/opa-examples.md) - OPA policy examples and testing

## Testing

```
go test ./...
```

All 121 tests should pass.
