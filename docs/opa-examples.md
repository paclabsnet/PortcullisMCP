# OPA Policy Examples for Portcullis

Portcullis enforces that every MCP tool call is evaluated by a Policy Decision
Point (PDP) before execution. **How you write that policy is entirely up to your
organization.** Portcullis ships two example Rego implementations to illustrate
the options — operators are expected to write their own policy suited to their
environment, groups, and tools.

| Example file | Approach |
|---|---|
| `policies/decision-handwritten.rego` | Explicit Rego rules — readable, auditable, easily reviewed by security teams |
| `policies/decision.rego` | Table-driven — rules read from `data.portcullis.policies`; populate via Data API, S3 bundles, LDAP, or any OPA data source |

Neither is "the right answer." Most organizations will start with hand-written rules
and migrate to table-driven as policy scope grows and an authoritative group/role
store becomes available.

## Table of Contents
- [What Portcullis Sends to OPA](#what-portcullis-sends-to-opa)
- [Example: Hand-written Rego Rules](#example-hand-written-rego-rules)
- [Example: Table-driven Policy](#example-table-driven-policy)
- [Loading Policy Data into OPA](#loading-policy-data-into-opa)
- [Escalation Token JWT Design](#escalation-token-jwt-design)
- [Example Requests and Expected Decisions](#example-requests-and-expected-decisions)
- [Testing Policies with OPA](#testing-policies-with-opa)

---

## What Portcullis Sends to OPA

Portcullis-keep sends an `EnrichedMCPRequest` to OPA wrapped in an `input` envelope.
All field names use **snake_case**.

```json
{
  "input": {
    "server_name": "filesystem",
    "tool_name": "write_file",
    "arguments": {
      "path": "/workspace/src/main.go",
      "content": "package main\n..."
    },
    "user_identity": {
      "user_id": "alice@example.com",
      "display_name": "Alice Developer",
      "groups": ["developers", "team-backend"],
      "source_type": "oidc",
      "raw_token": "eyJhbGc..."
    },
    "escalation_tokens": [
      {
        "token_id": "esc-12345",
        "raw": "eyJhbGc...",
        "granted_by": "bob.manager@example.com"
      }
    ],
    "session_id": "session-abc123",
    "request_id": "req-xyz789"
  }
}
```

OPA must return a response in this format:

```json
{
  "result": {
    "decision": "allow",
    "reason": "user is authorized to perform this action",
    "request_id": "req-xyz789"
  }
}
```

The `request_id` is echoed from the input for audit correlation.

---

## Example: Hand-written Rego Rules

`policies/decision-handwritten.rego` shows policy written as explicit Rego rules.
This approach is easy to read, diff, and audit — a security reviewer can read the
file and understand exactly what is permitted without knowing OPA internals.

The pattern is straightforward:
- `deny contains reason if { ... }` — accumulate deny reasons; any match = deny
- `escalate contains reason if { ... not valid_escalation_for_request }` — fire unless a valid escalation token covers the request
- `allow_matched if { ... }` — at least one must be true for allow to fire
- Decision priority: deny > escalate > allow > default deny

Snippet from the example:

```rego
# Contractors may not access the database at all.
deny contains "contractors may not access the database" if {
    input.server_name == "database"
    "contractors" in input.user_identity.groups
}

# Filesystem writes require manager approval (non-admins, no escalation token).
escalate contains "write operations require manager approval" if {
    input.tool_name in ["write_file", "edit_file", "delete_file", "move_file", "copy_file"]
    input.server_name == "filesystem"
    not "admin" in input.user_identity.groups
    not valid_escalation_for_request
}

# Developers and analysts may read from the filesystem.
allow_matched if {
    input.server_name == "filesystem"
    input.tool_name in ["read_text_file", "list_directory", "directory_tree",
                        "search_files", "search_within_files"]
    some group in ["developers", "analysts", "contractors"]
    group in input.user_identity.groups
}
```

Because `deny` and `escalate` are incremental rules (sets), you can split policy
across multiple files in the same OPA package — useful when different teams own
different server policies.

---

## Example: Table-driven Policy

`policies/decision.rego` shows policy written as a **generic table evaluator**.
It reads policy rules from `data.portcullis.policies` — an array of rule objects.
The Rego itself never changes; only the data changes — which means policy can be
managed by any system that can write to OPA's data document.

### Rule Object

| Field | Type | Required | Description |
|---|---|---|---|
| `id` | string | yes | Unique identifier for audit and debugging |
| `server` | string | yes | MCP server name, or `"*"` for any server |
| `tools` | [string] | no | Tool names this rule applies to; omit for any tool |
| `groups` | [string] | yes | User must be in at least one group |
| `action` | string | yes | `"allow"`, `"deny"`, or `"escalate"` |
| `reason` | string | yes | Returned to the caller on deny or escalate |
| `path_prefix` | string | no | Restrict to paths starting with this prefix |

### Evaluation semantics

1. All matching `deny` rules accumulate into a deny set — any match → `deny`
2. All matching `escalate` rules accumulate (suppressed by a valid escalation token) — any match → `escalate`
3. Any matching `allow` rule → `allow`
4. No match → default `deny`

### Example policy table

```json
{
  "portcullis": {
    "escalation_secret": "change-in-production",
    "policies": [
      {
        "id": "fs-reads",
        "server": "filesystem",
        "tools": ["read_text_file", "list_directory", "directory_tree",
                  "search_files", "search_within_files"],
        "groups": ["developers", "contractors", "analysts"],
        "action": "allow",
        "reason": "read access is permitted"
      },
      {
        "id": "fs-writes-admin",
        "server": "filesystem",
        "tools": ["write_file", "edit_file", "delete_file",
                  "copy_file", "move_file"],
        "groups": ["admin"],
        "action": "allow",
        "reason": "admin write access is permitted"
      },
      {
        "id": "fs-writes-developers",
        "server": "filesystem",
        "tools": ["write_file", "edit_file", "delete_file",
                  "copy_file", "move_file"],
        "groups": ["developers"],
        "action": "escalate",
        "reason": "write operations require manager approval"
      },
      {
        "id": "db-deny-contractors",
        "server": "database",
        "groups": ["contractors"],
        "action": "deny",
        "reason": "contractors may not access the database"
      },
      {
        "id": "db-reads",
        "server": "database",
        "tools": ["execute_query"],
        "groups": ["developers", "analysts"],
        "action": "allow",
        "reason": "database read access is permitted"
      },
      {
        "id": "enterprise-api-orders",
        "server": "mock-enterprise-api",
        "tools": ["update_order_status"],
        "groups": ["developers"],
        "action": "escalate",
        "reason": "order updates require manager approval"
      },
      {
        "id": "enterprise-api-delete-orders",
        "server": "mock-enterprise-api",
        "tools": ["delete_order"],
        "groups": ["admin"],
        "action": "allow",
        "reason": "admin can delete orders"
      }
    ]
  }
}
```

---

## Loading Policy Data into OPA

### Option A — OPA Data API (push)

Push the full data document at startup or whenever policy changes:

```bash
curl -X PUT http://localhost:8181/v1/data/portcullis \
  -H 'Content-Type: application/json' \
  -d @policy-data.json
```

Push only the policies array (leaves other `portcullis` keys intact):

```bash
curl -X PUT http://localhost:8181/v1/data/portcullis/policies \
  -H 'Content-Type: application/json' \
  -d @policies.json
```

Push revoked escalation token JTIs:

```bash
curl -X PUT http://localhost:8181/v1/data/portcullis/revoked_token_ids \
  -H 'Content-Type: application/json' \
  -d '["jti-to-revoke-1", "jti-to-revoke-2"]'
```

OPA re-evaluates on every request, so updates take effect immediately.

### Option B — OPA Bundles (pull from S3, GCS, HTTP, etc.)

OPA bundles let you store policy data in object storage and have OPA pull and
cache it automatically. Add to your OPA configuration:

```yaml
# opa-config.yaml
bundles:
  portcullis-policy:
    resource: "/v1/policies/portcullis"
    service: policy-server
    polling:
      min_delay_seconds: 60
      max_delay_seconds: 120

services:
  policy-server:
    url: "https://policy.internal.example.com"
    credentials:
      bearer:
        token_path: /var/run/secrets/policy-token
```

The bundle can contain both the Rego (from `policies/decision.rego`) and the
data document — operators update only the data file in the bundle.

### Option C — External data source plugins

OPA has community plugins for LDAP, databases, Consul, and other sources.
These can populate `data.portcullis.policies` from your authoritative group
and policy store without a separate ETL pipeline.

---

## Escalation Token JWT Design

Escalation tokens are signed JWTs that an approver (manager or workflow system)
sends to a user out-of-band (email, Slack DM) after approving an elevated action.
The user adds the JWT to their Portcullis Gate token store via the management UI;
the gate attaches it to every subsequent request until it expires.

The PDP is the sole authority on whether a token is valid and covers the request.
The gate only prunes expired tokens on load.

### Required claims

```json
{
  "sub": "alice@example.com",
  "jti": "550e8400-e29b-41d4-a716-446655440000",
  "iss": "portcullis-approver",
  "iat": 1700000000,
  "exp": 1700086400,
  "granted_by": "bob.manager@example.com",
  "portcullis": {
    "tools":       ["write_file", "edit_file"],
    "servers":     ["filesystem"],
    "path_prefix": "/workspace/feature-x/",
    "reason":      "Sprint 42 feature branch work"
  }
}
```

| Claim | Description |
|---|---|
| `sub` | User the grant is for — must match `input.user_identity.user_id` |
| `jti` | Unique token ID — enables revocation via OPA data |
| `exp` | Hard expiry — enforced automatically by `io.jwt.decode_verify` |
| `portcullis.tools` | Permitted tool names, or `["*"]` for any tool |
| `portcullis.servers` | Permitted server names, or `["*"]` for any server |
| `portcullis.path_prefix` | *(optional)* Restrict write access to a path subtree |

When a valid escalation token covers the request, any `escalate` rules that
would otherwise fire are suppressed, and the request is permitted directly.

### Signature verification

Configure exactly one of the following in your OPA data document:

**Option A — HMAC shared secret (HS256, development/simple deployments):**
```json
{ "portcullis": { "escalation_secret": "your-shared-secret-here" } }
```

**Option B — Asymmetric keys via JWKS (RS256/ES256, production-recommended):**
```json
{ "portcullis": { "escalation_jwks_url": "https://keys.internal.example.com/.well-known/jwks.json" } }
```

With Option B, OPA fetches and caches the public keys from the JWKS endpoint.
The token issuer (approval workflow) holds the corresponding private key.

### Revocation

Load revoked JTIs into OPA via the Data API; revocation takes effect immediately:

```bash
curl -X PUT http://localhost:8181/v1/data/portcullis/revoked_token_ids \
  -H 'Content-Type: application/json' \
  -d '["550e8400-e29b-41d4-a716-446655440000"]'
```

To check revocation in policy, add to `valid_escalation_for_request` in your
local Rego override:

```rego
not payload.jti in data.portcullis.revoked_token_ids
```

---

## Example Requests and Expected Decisions

### Example 1: Filesystem read (developer)

```json
{
  "input": {
    "server_name": "filesystem",
    "tool_name": "read_text_file",
    "arguments": { "path": "/workspace/README.md" },
    "user_identity": {
      "user_id": "alice@example.com",
      "groups": ["developers", "team-backend"],
      "source_type": "oidc"
    },
    "escalation_tokens": [],
    "session_id": "session-001",
    "request_id": "req-001"
  }
}
```

**Expected:** `allow` — matches rule `fs-reads` (developer in allowed groups)

---

### Example 2: Filesystem write without escalation token (developer, non-admin)

```json
{
  "input": {
    "server_name": "filesystem",
    "tool_name": "write_file",
    "arguments": { "path": "/workspace/src/critical.go", "content": "..." },
    "user_identity": {
      "user_id": "charlie@example.com",
      "groups": ["developers"],
      "source_type": "oidc"
    },
    "escalation_tokens": [],
    "session_id": "session-002",
    "request_id": "req-002"
  }
}
```

**Expected:** `escalate` — matches rule `fs-writes-developers`; no escalation token present

---

### Example 3: Filesystem write with a valid escalation token

The token covers `write_file` on `filesystem` for `charlie@example.com` within `/workspace/feature-x/`.
OPA verifies the signature, checks `sub`, `servers`, `tools`, and `path_prefix`.

```json
{
  "input": {
    "server_name": "filesystem",
    "tool_name": "write_file",
    "arguments": { "path": "/workspace/feature-x/handler.go", "content": "..." },
    "user_identity": {
      "user_id": "charlie@example.com",
      "groups": ["developers"],
      "source_type": "oidc"
    },
    "escalation_tokens": [
      {
        "token_id": "550e8400-e29b-41d4-a716-446655440000",
        "raw": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
        "granted_by": "bob.manager@example.com"
      }
    ],
    "session_id": "session-003",
    "request_id": "req-003"
  }
}
```

**Expected:** `allow` — `valid_escalation_for_request` is true; escalation rule suppressed

---

### Example 4: Escalation token for wrong user

Token `sub` is `dave@example.com` but requesting user is `charlie@example.com`.
`valid_escalation_for_request` is false; escalate rule still fires.

**Expected:** `escalate`

---

### Example 5: Database access by contractor

```json
{
  "input": {
    "server_name": "database",
    "tool_name": "execute_query",
    "arguments": { "query": "SELECT * FROM users" },
    "user_identity": {
      "user_id": "eve@example.com",
      "groups": ["contractors"],
      "source_type": "oidc"
    },
    "escalation_tokens": [],
    "session_id": "session-004",
    "request_id": "req-004"
  }
}
```

**Expected:** `deny` — matches rule `db-deny-contractors`

---

### Example 6: No matching rule (unknown server)

A request for a server/tool combination not covered by any policy rule returns
the default deny.

**Expected:** `deny` — "no policy matched, default deny"

---

## Testing Policies with OPA

### Running OPA locally

```bash
# Start OPA with the policy Rego and initial data
opa run --server --addr localhost:8181 \
  policies/decision.rego \
  --data policy-data.json

# Test a decision
curl -s -X POST http://localhost:8181/v1/data/portcullis/decision \
  -H 'Content-Type: application/json' \
  -d @test-request.json | jq .
```

### Unit testing with rego test

```rego
package portcullis_test

import rego.v1

# Shared mock data for tests
mock_data := {
    "portcullis": {
        "escalation_secret": "test-secret",
        "policies": [
            {
                "id": "fs-reads",
                "server": "filesystem",
                "tools": ["read_text_file"],
                "groups": ["developers"],
                "action": "allow",
                "reason": "read access permitted"
            },
            {
                "id": "fs-writes",
                "server": "filesystem",
                "tools": ["write_file"],
                "groups": ["developers"],
                "action": "escalate",
                "reason": "write operations require manager approval"
            },
            {
                "id": "fs-admin-writes",
                "server": "filesystem",
                "tools": ["write_file"],
                "groups": ["admin"],
                "action": "allow",
                "reason": "admin write permitted"
            }
        ]
    }
}

test_read_allowed if {
    result := data.portcullis.decision with input as {
        "tool_name": "read_text_file",
        "server_name": "filesystem",
        "user_identity": {"user_id": "alice@example.com", "groups": ["developers"]},
        "escalation_tokens": [],
        "arguments": {},
        "request_id": "req-test-1"
    } with data as mock_data
    result.decision == "allow"
}

test_write_escalates_without_token if {
    result := data.portcullis.decision with input as {
        "tool_name": "write_file",
        "server_name": "filesystem",
        "user_identity": {"user_id": "charlie@example.com", "groups": ["developers"]},
        "escalation_tokens": [],
        "arguments": {"path": "/workspace/x.go"},
        "request_id": "req-test-2"
    } with data as mock_data
    result.decision == "escalate"
}

test_admin_write_allowed if {
    result := data.portcullis.decision with input as {
        "tool_name": "write_file",
        "server_name": "filesystem",
        "user_identity": {"user_id": "alice@example.com", "groups": ["developers", "admin"]},
        "escalation_tokens": [],
        "arguments": {"path": "/workspace/x.go"},
        "request_id": "req-test-3"
    } with data as mock_data
    result.decision == "allow"
}

test_unknown_server_denied if {
    result := data.portcullis.decision with input as {
        "tool_name": "some_tool",
        "server_name": "unknown-server",
        "user_identity": {"user_id": "alice@example.com", "groups": ["developers"]},
        "escalation_tokens": [],
        "arguments": {},
        "request_id": "req-test-4"
    } with data as mock_data
    result.decision == "deny"
    result.reason == "no policy matched, default deny"
}

test_request_id_echoed if {
    result := data.portcullis.decision with input as {
        "tool_name": "read_text_file",
        "server_name": "filesystem",
        "user_identity": {"user_id": "alice@example.com", "groups": ["developers"]},
        "escalation_tokens": [],
        "arguments": {},
        "request_id": "req-echo-test"
    } with data as mock_data
    result.request_id == "req-echo-test"
}
```

Run tests:
```bash
opa test policies/ -v
```

---

## Extending Either Example

Because `deny`, `escalate`, and `allow_matched` are incremental rules (sets or
booleans contributed to by multiple definitions), any file in the same OPA package
can add to them without modifying the base policy file. This works with both the
hand-written and table-driven examples.

For example, to add a business-hours restriction across all policies, create a
separate file in the same package:

```rego
package portcullis

import rego.v1

# Contributes to the deny set regardless of which base policy file is loaded.
deny contains "access is only permitted during business hours (Mon–Fri 08:00–18:00 UTC)" if {
    now := time.now_ns()
    day  := time.weekday(now)   # 0=Sunday, 6=Saturday
    hour := time.clock(now)[0]
    any([day == 0, day == 6, hour < 8, hour >= 18])
}
```

Load both files together:

```bash
opa run --server policies/decision-handwritten.rego policies/business-hours.rego --data ...
```
