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

This separation ensures:
- Fast local operations (reads in sandbox)
- Policy-enforced enterprise access (writes, APIs, databases)
- Realistic enterprise architecture (no stdio in production)

### 1. Start OPA

```powershell
docker-compose up -d
```

This starts OPA on `http://localhost:8181` with the policies in the `policies/` directory.

### 2. Build the binaries

```powershell
go build -o bin/portcullis-keep.exe ./cmd/portcullis-keep
go build -o bin/portcullis-gate.exe ./cmd/portcullis-gate
```

### 3. Start the Mock HTTP MCP Server

In a separate terminal:

```powershell
go run ./examples/mock-enterprise-api
```

This starts a mock enterprise API server on `http://localhost:3000/mcp` with example tools:
- `get_customer` - Read customer data (allowed by policy)
- `query_inventory` - Check inventory (allowed by policy)
- `update_order_status` - Modify orders (requires escalation)

### 4. Start portcullis-keep

```powershell
.\bin\portcullis-keep.exe -config config/keep-config.minimal.yaml
```

This starts the Keep server on `http://localhost:8080` (no TLS for local testing).

### 5. Start portcullis-gate

In a separate terminal:

```powershell
.\bin\portcullis-gate.exe -config config/gate-config.minimal.yaml
```

This starts the Gate sidecar, which will connect to Keep.

### 6. Test it

The Gate exposes an MCP server on stdio. You can test it by connecting an MCP client or using the management API at `http://localhost:7777`.

**Testing the flow:**
- Local filesystem reads (Gate fast-path) - never reach Keep
- Enterprise API calls (mock-enterprise-api backend) - routed through Keep → OPA → Mock server
- Policy denies/escalations are visible in Keep logs
- Check OPA decisions: `curl http://localhost:8181/v1/data/portcullis/decision -d @test-request.json`

## Configuration

### Minimal (for local testing)
- `config/gate-config.minimal.yaml` - Local testing without TLS
- `config/keep-config.minimal.yaml` - Local testing without TLS

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

The included `policies/decision.rego` provides a minimal policy that:
- Allows filesystem reads in the sandbox
- Requires escalation for writes
- Denies access to protected paths (.git, .portcullis)

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

```powershell
go test ./...
```

All 121 tests should pass.
