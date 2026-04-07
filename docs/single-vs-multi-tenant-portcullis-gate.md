# Portcullis-Gate: Single-Tenant vs. Multi-Tenant Modes

Portcullis-Gate is the "Edge" of the Portcullis system. It is the primary interface for AI Agents to access secured MCP tools. Depending on your environment—an individual developer's desktop or a large-scale enterprise AI console—you will choose between two distinct deployment modes.

---

## At a Glance: Feature Comparison

| Feature | **Single-Tenant (Desktop/CLI)** | **Multi-Tenant (Console/Platform)** |
| :--- | :--- | :--- |
| **Primary User** | Individual Developer / AI Researcher | Enterprise AI Platform / Console Admins |
| **Deployment** | Local machine (Windows/Mac/Linux) | Kubernetes Cluster / Cloud Infrastructure |
| **Transport** | `stdio` (launched by local Agent) | `HTTP (SSE/Streamable)` (long-running) |
| **Identity Source** | Local OS / Interactive OIDC Login | Header-based (`X-Portcullis-Token`) |
| **State Storage** | Local Memory / JSON File | Distributed Redis |
| **Escalation** | Human-in-the-loop (Guard UI) | Policy-only (Deny/Allow) *[1]* |
| **Local Filesystem** | Enabled (FastPath support) | Disabled (Isolation requirement) |
| **Scaling** | Vertical (one gate per agent) | Horizontal (stateless cluster) |

*[1] Human-in-the-loop escalation for multi-tenant mode is on the roadmap and requires integration with centralized enterprise notification systems (e.g., Slack or Microsoft Teams), or a specialized web interface*

---

## 1. Single-Tenant Mode (Desktop & CLI)

In Single-Tenant mode, Portcullis-Gate is a lightweight utility that lives alongside the AI Agent (e.g., Claude Desktop, VS Code, or Cursor). It acts as a secure "wrapper" for the local environment.

### Use Case: The Protected Developer
A developer wants to use an AI agent to help with local coding, but they want to ensure the agent cannot accidentally delete their `.git` folder or overwrite their SSH keys.

### Key Capabilities:
- **Interactive OIDC Login:** Gate can launch a browser for the user to authenticate against the corporate IdP (Okta, Azure AD, etc.) using Authorization Code + PKCE.
- **Local Filesystem FastPath:** Gate provides its own `portcullis-localfs` MCP server. It uses a "FastPath" mechanism to allow safe reads/writes to a sandbox directory without ever reaching out to the network for policy decisions.
- **Human-in-the-Loop:** When a policy requires escalation, Gate provides the agent with a "Guard URL" that the user can click to approve the specific action.

---

## 2. Multi-Tenant Mode (Console & Platform)

In Multi-Tenant mode, Portcullis-Gate acts as a high-availability gateway for an enterprise AI platform. It is designed to be part of the infrastructure, not a local tool.

### Use Case: The Secure AI Console
An enterprise has built an internal "AI Assistant Console" for their employees. Thousands of users are logged into this console simultaneously, each with their own AI Agent session. The console needs to call internal enterprise APIs (via MCP tools) but must ensure that the AI Agent's access is strictly governed.

### Key Capabilities:
- **Stateless Scaling:** By using **Redis** for session storage and event streams, Multi-tenant Gate instances can be clustered behind a standard load balancer. If an instance restarts, the agent's connection can be picked up by another instance seamlessly.
- **Header-Based Identity:** Instead of an interactive login, the Gate extracts user identity from incoming HTTP headers (e.g., `X-Portcullis-Token`), allowing it to integrate with existing platform authentication.
- **Strict Isolation:** In this mode, Gate automatically disables dangerous features like `portcullis-localfs` and management APIs that could compromise the hosting infrastructure.

---

## The "Agent vs. User" Security Model

The most critical distinction in Portcullis security is the separation of **User Identity** from **Agent Intent**.

1. **User Identity:** "Who is sitting at the keyboard?" (e.g., Alice, a Senior Engineer).
2. **Agent Intent:** "What is the AI trying to do?" (e.g., `DROP TABLE production_orders`).

In traditional API security, if Alice is an "Admin," her session token allows her to drop a table. **Portcullis-Gate** adds a layer of "Agentic Policy." Even if Alice is an Admin, her AI Agent may be restricted to "Read-Only" by default. If the Agent tries to perform a high-risk action, Portcullis intervenes—not because Alice lacks permission, but because the **Agent** requires explicit human confirmation for that specific intent.

---

## Operational FAQ

### "How do I handle session affinity in a Multi-tenant cluster?"
Portcullis-Gate in multi-tenant mode is designed to be stateless. By using **Redis** as the storage backend, MCP sessions and event streams are shared across the cluster. You can use a standard Round-Robin load balancer without needing sticky sessions.

### "What happens to the MCP Event Stream if a Gate instance restarts?"
Because the event history is persisted in Redis, a new Gate instance can pick up the stream seamlessly using the `last_event_id` provided by the MCP client. This provides high availability for long-running agentic conversations.

### "Is there a performance bottleneck in the Multi-tenant Bridge?"
The Multi-tenant Gate is a lightweight pass-through. It performs identity extraction and adds trace context, then streams the response. The primary latency bottleneck remains the Backend MCP Tool itself (and the AI's "thinking" time), not the Portcullis infrastructure.

### "Can I mix modes?"
No. Each Portcullis-Gate instance is configured as either `tenancy: single` or `tenancy: multi`. A single instance cannot serve both desktop `stdio` agents and remote `HTTP` agents simultaneously. This ensures that security boundaries and resource limits are clearly defined for each deployment.
