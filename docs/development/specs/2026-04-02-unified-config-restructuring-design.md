# Unified Configuration Restructuring for Portcullis Services

**Date:** 2026-04-02
**Status:** Approved
**Topic:** Restructuring the YAML configuration files for Portcullis-Gate, Portcullis-Keep, and Portcullis-Guard into a unified, symmetrical, and domain-organized model.

## 1. Executive Summary
The existing configuration files for the Portcullis ecosystem provide the necessary information but lack a consistent organizational structure. This design introduces a **Unified Peer Model** where every service (Gate, Keep, Guard) shares a common top-level schema, standardizes internal communication authentication, and employs a "Strategy + Config" pattern for extensibility.

## 2. Architecture: The Unified Peer Model
Every Portcullis service is viewed as a peer with a specific domain of authority. To reflect this, all configuration files will adhere to the following five top-level blocks:

| Block | Purpose |
| :--- | :--- |
| `server` | Inbound connectivity via named `endpoints` (Listen, TLS, and Auth). |
| `identity` | User identity context, verification (OIDC), and normalization. |
| `peers` | Outbound connectivity and authentication for sibling Portcullis services. |
| `responsibility` | The specialized "duty" or "power" unique to this specific peer. |
| `operations` | Cross-cutting concerns: Storage, Telemetry, Logging, and System Limits. |

---

## 3. Specialized Responsibilities

### 3.1. Portcullis-Gate (The Agent Interface)
Gate manages the Agent's local environment and provides instructions back to the LLM.
- **`workspace.directories`**: Defines the "safe zone" where the Agent is permitted to read files freely, and write (with approval).
- **`forbidden.directories`**: Explicitly defines "forbidden" paths that the Agent is never allowed to access.
- **`agent_interaction`**: Templates for instructions returned to the AI for Deny, Escalate, or Workflow outcomes.


### 3.2. Portcullis-Keep (The Policy & Inventory Authority)
Keep acts as the Policy Decision Point (PDP) and maintains the inventory of MCP backends.
- **`policy`**: Configuration for the PDP engine (e.g., OPA).
- **`mcp_backends`**: Definitions for upstream MCP servers with standardized secret resolution (`envvar://`, `filevar://`, `vault://`).
- **`issuance`**: Signing logic for escalation *requests*.
- **`workflow`**: External approval triggers (ServiceNow, Webhooks, etc.) using the "Strategy + Config" pattern.

### 3.3. Portcullis-Guard (The Issuance & UI Authority)
Guard provides the human-facing interface for approvals and issues the final escalation tokens.
- **`issuance`**: Signing logic for approved escalation *tokens*.
- **`interface`**: HTML templates and UI-specific settings (e.g., management port reference).
- **`token_lifecycle`**: Management of pending/unclaimed tokens (TTL, cleanup).

---

## 4. Standardized Communication & Security

### 4.1. The "Strategy + Config" Pattern
To ensure future extensibility, blocks that support multiple implementations (Storage, Identity, Workflows) will use a consistent pattern:
- **`backend`** / **`source`** / **`strategy`**: A string identifying the implementation to use.
- **`config`**: A nested block containing the specific parameters for that implementation.

### 4.2. Server Endpoints (`server`)
Every peer listener is defined within a named endpoint under the `server` block. This allows services to host multiple roles (e.g., a UI and an API) with independent TLS and Auth settings.

- **`endpoints`**:
    - **`[name]`**: (e.g., `management_ui`, `approval_ui`, `token_api`)
        - `listen`: The "host:port" to bind to.
        - `tls`: Cert/Key for this specific endpoint.
        - `auth`: Inbound authentication requirement (`type` and `credentials`).

### 4.3. Peer Authentication (`peers`)
Outbound connections to other peers will use a standardized authentication block:
- **`auth`**:
    - **`type`**: `none`, `bearer`, or `mtls`.
    - **`credentials`**:
        - For `bearer`: `bearer_token` (resolved via secret URIs).
        - For `mtls`: `cert`, `key`, and optional `server_ca`.

### 4.3. Guard Endpoints
Connections to Guard must distinguish between human-facing and machine-facing URLs:
- **`endpoints`**:
    - `approval_ui`: The URL shown to users in their browser.
    - `token_api`: The internal API endpoint used by Gate/Keep.

---

## 5. Implementation Notes
- **Secret Resolution**: All sensitive fields (tokens, keys) must support one of the secret-aquisition uris to prevent secrets from being committed to version control.
- **Secret Restriction**: Only a specific set of the sensitive fields are allowed to use
`vault://` to acquire secrets, and that set is hard-coded
- **Code Impact**: The `internal/shared/config` package should be updated to provide a common parser for the shared blocks (`server`, `identity`, `peers`, `operations`).
- **Backward Compatibility**: This is a breaking change for configuration. Migration of existing `gate-config.yaml`, `keep-config.yaml`, and `guard-config.yaml` is required.

---

## 6. Self-Review
- **Placeholders**: None.
- **Consistency**: The `auth.credentials` and `strategy+config` patterns are applied uniformly.
- **Ambiguity**: The distinction between `workspace` and `restrictions` is now explicit.
- **Scope**: This spec covers the YAML structure only; implementation of the Go parser will follow in the implementation plan.
