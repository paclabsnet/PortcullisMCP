# PortcullisMCP

PortcullisMCP is an enterprise MCP (Model Context Protocol) policy gateway solution written in Go. It sits between AI agents and the MCP servers they call, enforcing access policy through an external Policy Decision Point (PDP) with full user identity context and enterprise workflow integration for escalations.

## The Problem

Enterprise AI agents need controlled access to tools (filesystem, APIs, databases, internal services) with the same policy rigor as human users: identity-aware decisions, audit trails, escalation to human approvers, and integration with existing enterprise workflow systems. Generic local policy enforcement (compile-time rules, single-user assumptions) does not meet this bar.

## Architecture

### Agent (Claude, Copilot, etc) 
on a user's machine.  Where appropriate, it is a managed binary, so the user can't change it. 
- all MCP interactions are sent to the MCP sidecar: portcullis-gate

### portcullis-gate
Acts as the local, lightweight proxy for the user's access to the MCPs,
both locally and across the enterprise.

- for performance reasons, it will typically allow local filesystem reads automatically
- all other MCP requests will be wrapped with identification and authorization tokens and sent to a central clearinghouse (portcullis-keep)
- the local read decisions will optionally be forwarded to a central clearinghouse (so all decisions are logged). This is optional since it is likely to be highly specific to each enterprise and will probably require custom development that is out of scope at the moment.

This then requires that the portcullis-gate be able to do the following things:
- accept identity tokens from the users (JWTs, other tokens TBD)
- accept 'escalation tokens' from the users (tokens which grant the user/agent temporary access to enterprise MCPs) 
- identify local filesystem read requests and (based on policy) pass those immediately to a local MCP
- wrap all other MCP requests with identity information and pass them on to the portcullis-keep
- send all local fast-path decision logs to portcullis-keep for centralized audit logging


### portcullis-keep
Acts as a central MCP proxy, responsible for authorizing all MCP requests against corporate policy rules using established policy as code solutions.

- it will accept the wrapped MCP requests from various portcullis-gate clients
- it will call a PDP to allow/deny/escalate the request, including the identity and escalation tokens
- in the 'deny' case it will return a deny response to portcullis-gate immediately
- in the 'allow' case it will acquire whatever authorization credentials are needed by the MCP (perhaps by calling a PDP, perhaps an API call to some sort of token exchange. This depends primarily on the credential requirements of the downstream MCP server and the enterprise security requirements).  And then send the request on to the appropriate MCP to perform the work. It will then capture the response, and send that response back to portcullis-gate
- in the 'escalate' case, it will call an enterprise-specific plugin to send the request to an enterprise workflow for approval (slack, servicenow, jira, etc)
- in the 'deny' case it sends the deny downstream to the portcullis-gate along with the reason text (if provided)



## Components

### portcullis-gate (local sidecar)

Runs on the developer's machine alongside the agent. Distributed as a single binary.

**MCP proxy** — presents itself to the agent as an MCP server (stdio or UDS transport). On `tools/list`, aggregates tool schemas from all configured MCP backends (via Keep) and passes them through. On `tools/call`, intercepts every request before forwarding.

**Structural fast-path** — two hardcoded rules evaluated locally with no network round-trip:
1. Filesystem ops whose paths are entirely within the configured sandbox directory → `allow` immediately
2. Any path matching the protected paths list → `deny` immediately

these rules will evaluate symlink and path traversal attacks before allowing


These are the only policy decisions portcullis-gate makes. All other requests go to portcullis-keep, enriched with identity and tokens. No compiled policy lives in portcullis-gate.

**User identity collection** — at session start, portcullis-gate resolves the local user's identity from configurable sources in priority order: OIDC/OAuth2 token from the enterprise IdP (preferred), OS username + machine identity as fallback. The resulting `UserIdentity` is attached to every request forwarded to portcullis-keep.  The portcullis-keep may be configured to disallow user-controlled naming, we provide it for testing/evaluation purposes

**Escalation token store** — a local JSON file (`~/.portcullis/tokens.json`) holding pre-authorization tokens the user has received out-of-band (e.g., a manager approved a destructive operation and sent a signed JWT). Portcullis-gate attaches all valid (non-expired) tokens to every upstream request; the PDP evaluates whether any token covers the requested operation. Portcullis-gate does not evaluate tokens itself.  If tokens are provided to portcullis-gate via an API or UI, portcullis-gate will update the `tokens.json` file appropriately.

This token store should be accessible only by the user, using OS-level permissions.

**Management API** — a localhost-only HTTP server for token CRUD. Tokens are added by pasting the JWT the user received. Expired tokens are pruned on load.  By default, this will not require additional authentication information. An enterprise may choose to require a shared secret or some other mechanism to prevent third-party attacks to create false JWTs

**Decision Log Batching** — fast-path decisions (allow/deny) are queued to a local buffered channel and sent to portcullis-keep in batches. Configurable flush interval (default: 30 seconds) and batch size (default: 100 entries). This reduces network overhead while ensuring audit trail completeness. Logging is non-blocking and best-effort to never impact agent performance.


### portcullis-keep (central enterprise service)

A long-lived HTTP service deployed by the enterprise. Optionally authenticates incoming requests from portcullis-gate instances via mTLS or a bearer token.

**PDPClient interface** — pluggable. Primary implementation calls the OPA (Open Policy Agent) REST API. The request body sent to the PDP is the full `EnrichedMCPRequest` (tool call + user identity + escalation tokens + session metadata). The PDP returns `allow`, `deny`, or `escalate` with a reason string and an audit ID.

**MCPRouter** — maintains connections to registered MCP backend servers (stdio child processes or HTTP/UDS transports). On `allow`, routes the tool call to the appropriate backend, collects the result, and returns it upstream. Backends are registered by name in Keep's config and match the server name in each `EnrichedMCPRequest`.

**WorkflowHandler interface** — pluggable. Called on `escalate`. Implementations:
- **ServiceNow**: opens a change request. Approver will need to send a JWT to the appropriate user.
- **Webhook**: HTTP POST to a configurable URL. Approver will need to send a JWT to the appropriate user.
- **Other** : TBD - but same general pattern - approval happens out of band, and the Portcullis-keep is not involved after the initial request.

Escalation is asynchronous and the escalation tokens are not generated by Portcullis. Portcullis-keep returns an `escalation_pending` response. Portcullis-gate surfaces this to the agent (MCP error). The enterprise workflow resolves asynchronously, and an appropriate JWT is sent to the user out-of-band. The escalation process is stateless on the Portcullis-keep side - it fires a request to 
the appropriate workflow and then forgets.  This potentially creates a risk of multiple requests for the same user for the same resource, but that problem can be resolved by the workflow.

**Decision Logger** — batches and forwards all policy decisions (both PDP decisions and fast-path decisions from gate instances) to a configurable SIEM or audit system. Uses a channel-based architecture with configurable buffer sizes, flush intervals, and batch sizes. Logs are compressed with gzip before transmission. Supports console logging for development and remote HTTP endpoints for production. All decision logs include complete context: timestamp, session ID, request ID, user ID, tool name, decision, reason, and arguments.

## Key Go Types

```go
// Shared between portcullis-gate and portcullis-keep (internal/shared/types.go)

type UserIdentity struct {
    UserID      string            // stable enterprise identifier (UPN, email, etc.)
    DisplayName string
    Groups      []string          // for PDP group-based policy
    SourceType  string            // "oidc" | "os"
    RawToken    string            // original OIDC token for PDP verification
}

type EscalationToken struct {
    TokenID   string
    Raw       string    // signed JWT as received
    GrantedBy string    // display name of approver
}

type EnrichedMCPRequest struct {
    ServerName       string
    ToolName         string
    Arguments        map[string]any
    UserIdentity     UserIdentity
    EscalationTokens []EscalationToken
    SessionID        string
    RequestID        string    // gate-generated UUID per call
}

type PDPResponse struct {
    Decision  string    // "allow" | "deny" | "escalate"
    Reason    string
    AuditID   string
}

// MCPToolSchema and MCPResult are not defined here — use *mcp.Tool and
// *mcp.CallToolResult from github.com/modelcontextprotocol/go-sdk/mcp directly.

```

## Interfaces

```go
// internal/keep/pdp.go
type PolicyDecisionPoint interface {
    Evaluate(ctx context.Context, req EnrichedMCPRequest) (PDPResponse, error)
}

// internal/keep/workflow.go
type WorkflowHandler interface {
    Submit(ctx context.Context, req EnrichedMCPRequest, pdpReason string) (requestID string, err error)
}

// internal/keep/router.go
// Uses *mcp.Tool and *mcp.CallToolResult from github.com/modelcontextprotocol/go-sdk/mcp
type MCPBackend interface {
    CallTool(ctx context.Context, serverName, toolName string, args map[string]any) (*mcp.CallToolResult, error)
    ListTools(ctx context.Context, serverName string) ([]*mcp.Tool, error)
}
```

## Directory Structure

```
portcullis/
├── cmd/
│   ├── portcullis-gate/
│   │   └── main.go
│   └── portcullis-keep/
│       └── main.go
├── internal/
│   ├── shared/
│   │   └── types.go              # EnrichedMCPRequest, UserIdentity, EscalationToken, etc.
│   ├── gate/
│   │   ├── server.go             # MCP server (agent-facing, stdio/UDS)
│   │   ├── fastpath.go           # sandbox containment + protected path checks
│   │   ├── forwarder.go          # HTTP client to Keep
│   │   ├── identity.go           # UserIdentity collection (OIDC, OS fallback)
│   │   ├── tokenstore.go         # EscalationToken persistence + API handlers
│   │   ├── api.go                # localhost management HTTP server
│   │   └── log.go                # writes local decisions to central server
│   └── keep/
│       ├── server.go             # HTTP server (gate-facing); holds in-memory pending escalation state
│       ├── pdp.go                # PDPClient interface + OPA implementation
│       ├── router.go             # MCPBackend interface + stdio/HTTP implementations
│       ├── workflow.go           # WorkflowHandler interface
│       ├── workflow_servicenow.go
│       └── workflow_webhook.go
├── config/
│   ├── gate-config.example.yaml
│   └── keep-config.example.yaml
├── go.mod                        # module: github.com/<org>/portcullis
└── CLAUDE.md
```

## Configuration

### Portcullis-Gate (`~/.portcullis/gate.yaml`)

```yaml
keep:
  endpoint: "https://portcullis.internal.example.com"
  auth:
    type: "mtls"          # or "bearer"
    cert: "~/.portcullis/gate.crt"
    key:  "~/.portcullis/gate.key"

identity:
  source: "oidc"          # or "os"
  oidc:
    token_file: "~/.portcullis/oidc-token"  # refreshed by enterprise SSO tooling

sandbox:
  directory: "~/.portcullis/sandbox"

protected_paths:
  - "~/.ssh"
  - "~/.portcullis"
  - "/etc"

management_api:
  port: 7777              # localhost only

token_store: "~/.portcullis/tokens.json"

transport: "stdio"        # or "uds"
uds_path: "/tmp/portcullis-gate.sock"

#
# example implementation, others TBD
#
decision_log:
  url: ${DECISION_LOG_SERVER}
  headers:
    X-API-KEY: ${DECISION_API_KEY}

```

### Portcullis-Keep (`/etc/portcullis/keep.yaml`)

```yaml
listen:
  address: "0.0.0.0:8443"
  tls:
    cert: "/etc/portcullis/keep.crt"
    key:  "/etc/portcullis/keep.key"
    client_ca: "/etc/portcullis/client-ca.crt"   # for mTLS gate auth

pdp:
  type: "opa"
  endpoint: "http://opa.internal.example.com:8181/v1/data/portcullis/decision"

backends:
  filesystem:
    type: "stdio"
    command: "npx"
    args: ["-y", "@modelcontextprotocol/server-filesystem", "/workspace"]
  github:
    type: "stdio"
    command: "npx"
    args: ["-y", "@modelcontextprotocol/server-github"]
    env:
      GITHUB_TOKEN: "${GITHUB_TOKEN}"

escalation:
  workflow:
    type: "servicenow"    # or "webhook"
    servicenow:
      instance: "example.service-now.com"
      credential_env: "${SNOW_CREDENTIALS}"

```

## MCP SDK

Use the official Go MCP SDK: `github.com/modelcontextprotocol/go-sdk`. Gate uses the server-side API to face the agent and the client-side API to call Keep (over HTTP). Keep uses the client-side API to call MCP backends.

## What the PDP Receives
The PDP receives a classic authorization request:
- Principal:  the set of credentials provided by the user, including any escalation tokens
- Action: the MCP request
- Resource: the MCP tool for which this request is being made


The PDP is responsible for:
- Evaluating tool call arguments against policy rules
- Validating and evaluating escalation token scopes
- Group/role-based access control using `UserIdentity.Groups`
- Writing the authoritative audit record
- Returning `allow` | `deny` | `escalate` with a reason

Portcullis does not define PDP policy — that is the operator's domain (OPA Rego, custom service, etc.).

## Key Conventions

- Standard Go project layout (`cmd/`, `internal/`)
- No global state; configuration and dependencies injected at startup
- All interfaces defined in the package that consumes them (not the package that implements them)
- Context propagation throughout — every public function that does I/O takes `context.Context` as its first argument
- Errors returned, not panicked; sentinel errors for known failure modes (`ErrDenied`, `ErrEscalationPending`, `ErrPDPUnavailable`)
- Configuration via YAML files; no environment variable policy (env vars only for secrets referenced from config)
- Tests use table-driven style with `t.Run`; integration tests tagged `//go:build integration`



