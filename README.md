# PortcullisMCP

**Enterprise MCP (Model Context Protocol) Policy Gateway**

PortcullisMCP is a policy enforcement gateway for AI agents. It sits between AI agents (Claude, Copilot, etc.) and MCP servers, enforcing access policies through an external Policy Decision Point (PDP).

PortcullisMCP is designed to be unopinionated: bring your own PDP, your own identity provider, your own workflow system, and your own secret management. The core loop stays minimal so you can get started without heavy infrastructure.

## Architecture

For a detailed breakdown of components and communication flows, see [ARCHITECTURE.md](./ARCHITECTURE.md).

```
Agent <--> portcullis-gate <--> portcullis-keep <--> PDP (OPA or custom)
                          |                    |
                          |                    +--> HTTP MCP Backends
                          |                         (APIs, databases, enterprise services)
                          |
                          +--> Local Filesystem (fast-path, no network)
```

- **portcullis-gate**: Local sidecar on the user's machine. Handles local filesystem access via fast-path rules and forwards all other requests to Keep with full identity context.
- **portcullis-keep**: Central policy enforcement service. Calls the PDP, routes allowed requests to MCP backends, and handles escalations.
- **portcullis-guard**: Web UI for escalation approvals. Users click a link, review what the agent is requesting, and approve or deny.
- **PDP**: Policy Decision Point. The default integration is OPA (Open Policy Agent), but any HTTP service implementing the same interface works. A built-in `noop` PDP allows all requests — useful for getting started without a policy engine.

## Quick Start

### Prerequisites

- **Go 1.24+**
- **Docker** (optional, for full demo stack)
- **Make** (standard on Linux/Mac; see below for Windows)

#### Installing Make on Windows
If you don't have `make` installed, the easiest way is via a package manager:
- **Winget (Built-in):** `winget install ezwinports.make`
- **Chocolatey:** `choco install make`
- **Scoop:** `scoop install make`

Alternatively, if you have **Git for Windows** installed, you can use `mingw32-make` (you may want to alias it to `make`).

### Minimal (no Docker, no OPA)

This path runs Keep with the `noop` PDP, which allows all requests. Useful for understanding the flow before adding policy enforcement.

**Prerequisites:** Go 1.24+

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
        "args": ["-config", "/home/you/.portcullis/gate.yaml"]
    }
}
```

Copy `config/gate-config.minimal.yaml` to `~/.portcullis/gate.yaml` and adjust paths. Gate starts automatically when the MCP client launches.

Verify Gate is running via the management API at `http://localhost:7777`.

### Full Demo Stack (Docker)

This path runs the complete stack: OPA with a sample policy, Keep, Guard, and two example MCP backends (a mock enterprise API and a web fetch server).

**Prerequisites:** Go 1.24+, Docker

To build the binaries and start the demo:

#### Linux / Mac / Unix / Windows (familiar with golang)
```sh
make build && make install && make demo-start
```

#### Windows, Not familiar with golang

The instructions for installing make on Windows are included in the Quickstart instructions above.

`make build`

find portcullis-gate.exe

put it in `C:\Tools`
 - when you create your MCP configuration, tell it to find the binary in C:\Tools\portcullis-gate.exe

finally
`make demo-start` which will start the set of docker processes

#### Docker Demo 
Services started:
- Keep on `http://localhost:8080`
- Guard on `http://localhost:8444`
- OPA on `http://localhost:8181`
- Mock enterprise API and fetch-mcp (internal to Docker network)

Configure Gate as above, then try these prompts with your agent:

```
"what services are available from portcullis mcp?"

"Please use portcullis to fetch the latest news from <website>"

"Please use portcullis to query orders for customer <id>"

"Please use portcullis to update the name of customer <id> to Arbitrary Name"
```

The last request should trigger an escalation. The agent will present a link to you (the user). Click it, review the request in Guard. It should be a request to allow the update_customer tool to update the customer you  and approve it.
Then ask the agent to try again — this time it should succeed.

```sh
# Stop the demo stack
make demo-stop
```

## Configuration

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

Both Gate and Keep configs support `${VAR}` syntax for environment variable expansion. Use this for secrets rather than hardcoding them:

```yaml
backends:
  github:
    type: "stdio"
    command: "npx"
    args: ["-y", "@modelcontextprotocol/server-github"]
    env:
      GITHUB_TOKEN: "${GITHUB_TOKEN}"
```

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
- User identity — OIDC/OAuth2 or OS fallback (OS identity is for testing only; Keep strips unverifiable claims in strict mode)
- Escalation tokens — pre-authorized operations via signed JWTs
- Pluggable PDP — OPA integration included; noop PDP for getting started
- Workflow integration — ServiceNow, webhooks, or URL-based approval via Guard
- Audit logging — batched decision logs to SIEM or console
- Transport support — stdio and HTTP (Streamable HTTP, SSE) for MCP backends
- Optional TLS — mTLS for production, plain HTTP for development
- Bearer auth — shared secret authentication between Gate and Keep

## Testing

```sh
go test ./...
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Security

To report a vulnerability, see [SECURITY.md](SECURITY.md).

## License

Apache License 2.0. See [LICENSE](LICENSE).
