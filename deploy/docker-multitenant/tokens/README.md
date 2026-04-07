# Demo Tokens

These three tokens represent tenants with different levels of access. They are
pre-generated 10-year JWTs signed by mock-idp.dev (RS256). If they expire or
you need to regenerate them, visit https://mock-idp.dev and use the claim sets
below.

### Starting Multitenant Docker
in the deploy/docker-multitenant directory:
`docker compose up --build`

## Token files

| File | Sub and Email | Groups | Access |
|------|--------|--------|--------|
| `alice.jwt` | alice@example.com | `admin` | All tools |
| `bob.jwt` | bob@example.com | `developer` | All tools |
| `charlie.jwt` | charlie@example.com | `intern` | All tools |



## Access matrix (from existing OPA policy in policies/rego/data.json)

| Tool | alice (admin) | bob (developer) | charlie (intern) |
|------|:---:|:---:|:---:|
| `get_customer` | yes | yes | no |
| `query_inventory` | yes | yes | yes |
| `update_order_status` | yes | no | no |
| `delete_order` | yes | no | no |
| `fetch_url` | yes | yes | yes |

## Using the tokens

Pass the token as a bearer token in the `Authorization` header when connecting
your MCP client to `http://localhost:9090/mcp`. For example with curl:

```
export TOKEN=$(cat tokens/alice.jwt)
curl -H "Authorization: Bearer $TOKEN" http://localhost:9090/mcp
```

MCP client config (Claude Desktop / similar):

```json
{
  "mcpServers": {
    "portcullis": {
      "url": "http://localhost:9090/mcp",
      "headers": {
        "Authorization": "Bearer <contents of alice.jwt>"
      }
    }
  }
}
```

*note* in a production solution, such as an ai-enabled console, you will have a different way to attaching the mcp to the Agent

## Regenerating tokens at mock-idp.dev

Visit https://mock-idp.dev and create a token with the following settings.
Set expiry to 10 years. The issuer and audience are fixed.

**Required for all tokens:**

| Claim | Value |
|-------|-------|
| `iss` | `https://mock-idp.dev` |
| `aud` | `portcullis-mcp` |

*note*: `iss` will be correct by default, but `aud` is incorrect by default

**alice.jwt**

| Claim | Value |
|-------|-------|
| `sub` | `alice@example.com` |
| `email` | `alice@example.com` |
| `name` | `Alice Admin` |
| `groups` | `["admin"]` |

**bob.jwt**

| Claim | Value |
|-------|-------|
| `sub` | `bob@example.com` |
| `email` | `bob@example.com` |
| `name` | `Bob Developer` |
| `groups` | `["developer"]` |

**charlie.jwt**

| Claim | Value |
|-------|-------|
| `sub` | `charlie@example.com` |
| `email` | `charlie@example.com` |
| `name` | `Charlie Intern` |
| `groups` | `["intern"]` |
