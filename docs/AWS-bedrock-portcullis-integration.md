# Integrating Portcullis Gate with Amazon Bedrock AgentCore

**Audience:** IT administrator configuring a Bedrock-based AI agent to call tools exposed through Portcullis Gate.

**What this achieves:** Your Bedrock agent will discover and invoke tools published by Portcullis Gate through the AgentCore Gateway. Portcullis's policy enforcement, audit logging, and escalation controls remain fully in effect — from Gate's perspective, the Gateway is simply an authenticated MCP client.

---

## Prerequisites

Before starting, confirm the following:

- You have AWS credentials with permissions to create AgentCore Gateway resources (see IAM policy requirements below)
- Portcullis Gate is deployed and reachable via **HTTP transport** from within your AWS network or over a public/private endpoint
- Gate's MCP endpoint is live and responding to `tools/list` requests
- You have Gate's base URL
- Gate uses Bearer tokens for client credentials. 
- Gate currently supports MCP protocol version `2025-11-25` and `2025-06-18` 
    - As of this writing, AgentCore supports `2025-06-18` and `2025-03-26`

---

## Step 1: Ensure Gate Is Accessible via HTTP

AgentCore Gateway calls your MCP server over HTTPS. Gate must be running with `transport: http` in its configuration, not `stdio`. Confirm with your Portcullis administrator that:

- Gate is listening on a stable, routable URL (e.g., `https://portcullis.internal.example.com/mcp`)
- TLS is configured (AgentCore Gateway requires HTTPS for production targets)
  - Gate does not support TLS natively, put it behind something that terminates TLS
- Gate's inbound auth is set to validate Bearer tokens issued by an OAuth client credentials flow — this is how Gateway will authenticate when calling Gate

---

## Step 2: Register an OAuth Client Credential in AgentCore Identity

AgentCore Gateway uses **AgentCore Identity** to manage the credentials it presents when calling your MCP server outbound. You need to register a client credential that Gate will trust.

In the AWS Console or via CLI, navigate to **Bedrock AgentCore → Identity** and create a new OAuth2 client credential:

- Grant type: **client_credentials** (two-legged OAuth)
- The client ID and secret will be provided to you after creation
- Note the token endpoint AgentCore will use

Provide the resulting **client ID** and **client secret** to your Portcullis administrator so they can configure Gate to accept tokens issued to this client. Gate will validate the token on every inbound request.

**Note for Portcullis Admins**

Portcullis-Keep validates these client credentials. It supports both oidc and hmac based verification.  Make sure that the Portcullis-Keep identity strategy is hmac-verify and that the config includes the client secret.


---

## Step 3: Create the AgentCore Gateway

If you don't already have an AgentCore Gateway instance, create one:

```bash
aws bedrock-agentcore create-gateway \
  --name "portcullis-gateway" \
  --role-arn "arn:aws:iam::YOUR_ACCOUNT:role/AgentCoreGatewayRole" \
  --region us-east-1
```

Note the `gatewayId` returned — you'll use it in the next step.

The IAM role attached to the Gateway needs at minimum:

```json
{
  "Effect": "Allow",
  "Action": [
    "bedrock-agentcore:CreateGateway",
    "bedrock-agentcore:GetGateway",
    "bedrock-agentcore:CreateGatewayTarget",
    "bedrock-agentcore:GetGatewayTarget",
    "bedrock-agentcore:SynchronizeGatewayTargets",
    "bedrock-agentcore:UpdateGatewayTarget",
    "bedrock-agentcore:GetWorkloadAccessToken",
    "bedrock-agentcore:GetResourceOauth2Token",
    "secretsmanager:GetSecretValue"
  ],
  "Resource": "*"
}
```

---

## Step 4: Register Portcullis Gate as a Gateway Target

This is the core registration step. You're telling AgentCore Gateway where Gate lives and how to authenticate to it:

```bash
aws bedrock-agentcore create-gateway-target \
  --gateway-id "YOUR_GATEWAY_ID" \
  --name "portcullis-gate" \
  --endpoint "https://portcullis.internal.example.com/mcp" \
  --mcp-protocol-version "2025-03-26" \
  --outbound-auth '{
    "type": "OAUTH",
    "oauthConfig": {
      "clientId": "YOUR_AGENTCORE_CLIENT_ID",
      "clientSecretArn": "arn:aws:secretsmanager:us-east-1:YOUR_ACCOUNT:secret/portcullis-client-secret"
    }
  }'
```

Store the client secret in AWS Secrets Manager and reference it by ARN rather than passing it inline.

**What happens at this point:** AgentCore Gateway will immediately call Gate's `tools/list` endpoint to discover available tools and index them into its internal catalog. If this call fails (auth error, unreachable endpoint, protocol mismatch), the target registration will fail with a descriptive error. Work with your Portcullis administrator to resolve any auth handshake issues.

---

## Step 5: Verify Tool Discovery

Confirm that Gateway successfully indexed Gate's tools:

```bash
aws bedrock-agentcore get-gateway-target \
  --gateway-id "YOUR_GATEWAY_ID" \
  --target-id "YOUR_TARGET_ID"
```

The response should include the list of tools discovered from Gate. If Gate's tool definitions change later (e.g., new policies expose or restrict tools), trigger a manual re-sync:

```bash
aws bedrock-agentcore synchronize-gateway-targets \
  --gateway-id "YOUR_GATEWAY_ID"
```

---

## Step 6: Configure Your Bedrock Agent to Use the Gateway

In your Bedrock Agent configuration, point the agent at the Gateway's unified MCP endpoint. The specific configuration varies by framework (Strands Agents, LangGraph, etc.), but the pattern is the same — the agent uses the Gateway's endpoint URL as its MCP server, and Gateway proxies calls through to Gate.

For a Strands Agents–based agent, the relevant configuration looks like:

```python
from strands import Agent
from strands.tools.mcp import MCPClient

mcp_client = MCPClient(
    endpoint="https://bedrock-agentcore.us-east-1.amazonaws.com/gateways/YOUR_GATEWAY_ID/mcp",
    auth=SigV4Auth(region="us-east-1", service="bedrock-agentcore")
)

agent = Agent(tools=mcp_client.tools)
```

The agent authenticates to Gateway via IAM SigV4; Gateway authenticates to Portcullis Gate via the OAuth client credential you configured in Steps 2 and 4.

---

## Step 7: Confirm End-to-End Policy Enforcement

Work with your Portcullis administrator to validate that:

- Tool invocations from the Gateway appear in Gate's audit log with the correct principal (the AgentCore OAuth client identity)
- Policies are evaluating correctly against that principal
- If a tool invocation is denied by policy, the denial propagates back through Gateway to the agent as expected
- If Gate's escalation flow is in use, confirm that escalation requests surface appropriately (note: AgentCore Gateway's synchronous call model may require additional design for async escalation)

---

## Ongoing Maintenance

| Event | Action Required |
|---|---|
| Gate's tool definitions change | Call `SynchronizeGatewayTargets` |
| OAuth client secret rotated | Update the secret in Secrets Manager; no Gateway reconfiguration needed |
| Gate endpoint URL changes | Call `UpdateGatewayTarget` with the new URL |
| New Portcullis tenant added | Register a new Gateway Target for that tenant's Gate endpoint |

---

**Questions or issues during setup** should be directed to your Portcullis administrator for anything involving Gate's inbound auth configuration, policy behavior, or tool definitions, and to your AWS account team for AgentCore Gateway provisioning issues.
