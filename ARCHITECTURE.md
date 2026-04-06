# PortcullisMCP Architecture

PortcullisMCP is an enterprise MCP (Model Context Protocol) policy gateway solution written in Go. It sits between AI
agents and the MCP servers they call, enforcing access policy through an external Policy Decision Point (PDP) with full
user identity context and enterprise workflow integration for escalations.

## The Problem

Enterprise AI agents need controlled access to tools (filesystem, APIs, databases, internal services) with the same
policy rigor as human users: identity-aware decisions, audit trails, escalation to human approvers, and integration with
existing enterprise workflow systems. Generic local policy enforcement (compile-time rules, single-user assumptions)
does not meet this bar.

## System Overview

### Agent (Claude, Copilot, etc.)
Runs on a user's machine. Where appropriate, it is a managed binary, so the user can't change it.
- All MCP interactions are sent to the local proxy: `portcullis-gate`

### portcullis-gate
Acts as the local, lightweight proxy for the user's access to the MCPs.

- **Fast-path:** For performance, it allows local filesystem reads automatically based on configured sandbox rules.
- **Enrichment:** Wraps all other MCP requests with identification and authorization tokens.
- **Forwarding:** Sends enriched requests to `portcullis-keep` for central authorization.
- **Audit:** Sends fast-path decision logs to `portcullis-keep` for centralized audit logging.
- **Identity:** Resolves local user identity (OIDC or OS-fallback).
- **Escalation:** Manages a local token store for approved escalation JWTs.  This allows Human-in-the-loop authorization

**NOTE**
We've recently expanded the responsibilities for Portcullis-Gate .  In addition to being a lightweight proxy for a single-user desktop scenario, it can also be used as a lightweight proxy for enterprise AI-enabled consoles. In this case:
- It is a server that supports multiple agents in parallel
- It doesn't provide escalation services
- It can be clustered and connected to a distributed cache (redis) for fault-tolerance and HA

If you're building some sort of ai-enhanced console for your customers, this model for Portcullis-Gate would help you cleanly separate authorization from the AI's decision process.

### portcullis-keep
Acts as a central MCP proxy, responsible for authorizing all MCP requests against corporate policy rules.
- **Authorization:** Calls a PDP (e.g., OPA) to allow/deny/escalate requests using full context.
- **Routing:** On `allow`, routes requests to the appropriate backend MCP server (stdio, HTTP, etc.).
- **Escalation:** On `escalate`, sends information back to the `portcullis-gate` and eventually the user for
  authorization

### portcullis-guard
A web-based service where users or administrators approve pending escalation requests.
- **Verification:** Shows the details of the requested tool call and requested scope.
- **Signing:** On approval, issues a signed `escalation_token` JWT.
- **Claiming:** Provides an API for `portcullis-gate` to claim approved tokens asynchronously.

## Components

### portcullis-gate

Runs on the developer's machine alongside the agent.

- **MCP proxy** — presents itself as an MCP server (stdio or UDS). Aggregates tool schemas from Keep.
- **Structural fast-path** — local rules for sandbox containment and protected path denial.
- **User identity collection** — resolves identity via OIDC (preferred) or OS-identity.
- **Escalation token store** — local JSON file (`~/.portcullis/tokens.json`) for persistence.
- **Management API** — localhost HTTP server for token CRUD.
- **Decision Log Batching** — buffered channel for non-blocking audit logging to Keep.

### portcullis-keep

Central enterprise service.

- **PDPClient interface** — pluggable. Primary implementation calls OPA REST API.
- **MCPRouter** — maintains connections to registered MCP backend servers.
- **WorkflowHandler interface** — pluggable (ServiceNow, Webhook, URL).
- **Decision Logger** — batches and forwards logs to SIEM/audit systems.

## Key Go Types

```go
type UserIdentity struct {
    UserID      string
    DisplayName string
    Groups      []string
    SourceType  string            // "oidc" | "os"
    RawToken    string            // original OIDC token
}

// Principal represents verified user identity facts.
type Principal struct {
    UserID      string
    Email       string
    DisplayName string
    Groups      []string
    SourceType  string
}

type EscalationToken struct {
    TokenID   string
    Raw       string
    GrantedBy string
}

type EnrichedMCPRequest struct {
    ServerName       string            `json:"server_name"`
    ToolName         string            `json:"tool_name"`
    Arguments        map[string]any    `json:"arguments"`
    UserIdentity     UserIdentity      `json:"user_identity"`
    EscalationTokens []EscalationToken `json:"escalation_tokens"`
    SessionID        string            `json:"session_id"`
    TraceID          string            `json:"trace_id"`
}

// AuthorizedRequest represents a verified internal request.
type AuthorizedRequest struct {
    ServerName       string
    ToolName         string
    Arguments        map[string]any
    SessionID        string
    TraceID          string
    EscalationTokens []shared.EscalationToken
    Principal        shared.Principal
}

type PDPResponse struct {
    Decision        string         // "allow" | "deny" | "escalate"
    Reason          string
    EscalationScope []map[string]any
}
```

## Directory Structure

```
portcullis/
├── cmd/
│   ├── portcullis-gate/
│   ├── portcullis-keep/
│   └── portcullis-guard/
├── internal/
│   ├── shared/             # Shared types and utilities
│   ├── gate/               # Gate proxy logic
│   ├── keep/               # Central keep logic
│   └── guard/              # Approval web service
├── config/                 # Example configurations
└── policies/               # OPA/Rego policy examples
```

## Communication Flow

1. **User Request:** Agent calls a tool.
2. **Gate Interception:** Gate checks the local fast-path (sandbox).
3. **Keep Authorization:** If not fast-path, Gate forwards an `EnrichedMCPRequest` to Keep.
4. **PDP Evaluation:** Keep calls the PDP with the request context.
5. **Outcome:**
   - **Allow:** Keep forwards call to backend MCP, returns result to Gate.
   - **Deny:** Keep returns error message.
   - **Escalate:** Keep triggers workflow and returns an escalation URL to the user.
6. **Approval:** User visits Guard via the URL, approves, and Gate polls/claims the new token.
7. **Retry:** Agent retries the tool call; Gate now includes the escalation token in the request.
