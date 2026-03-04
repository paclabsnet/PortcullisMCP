# OPA Policy Examples for Portcullis

This document provides example OPA requests and policy rules for the Portcullis MCP gateway.

## Table of Contents
- [What Portcullis Sends to OPA](#what-portcullis-sends-to-opa)
- [Example OPA Requests](#example-opa-requests)
- [Example OPA Policy Rules](#example-opa-policy-rules)
- [Testing Policies with OPA](#testing-policies-with-opa)

## What Portcullis Sends to OPA

Portcullis-keep sends an `EnrichedMCPRequest` to OPA wrapped in an `input` envelope:

```json
{
  "input": {
    "serverName": "filesystem",
    "toolName": "write_file",
    "arguments": {
      "path": "/workspace/src/main.go",
      "content": "package main\n..."
    },
    "userIdentity": {
      "userID": "alice@example.com",
      "displayName": "Alice Developer",
      "groups": ["developers", "team-backend"],
      "sourceType": "oidc",
      "rawToken": "eyJhbGc..."
    },
    "escalationTokens": [
      {
        "tokenID": "esc-12345",
        "raw": "eyJhbGc...",
        "grantedBy": "bob.manager@example.com"
      }
    ],
    "sessionID": "session-abc123",
    "requestID": "req-xyz789"
  }
}
```

OPA must return a response in this format:

```json
{
  "result": {
    "decision": "allow",  // or "deny" or "escalate"
    "reason": "User is in developers group",
    "requestID": "req-xyz789"
  }
}
```

Note: Portcullis uses the `requestID` from the original request for audit tracing, so there's no need for OPA to generate a separate audit identifier.

---

## Example OPA Requests

### Example 1: Filesystem Read (should allow for developers)

**Request to OPA:**
```json
{
  "input": {
    "serverName": "filesystem",
    "toolName": "read_file",
    "arguments": {
      "path": "/workspace/README.md"
    },
    "userIdentity": {
      "userID": "alice@example.com",
      "displayName": "Alice Developer",
      "groups": ["developers", "team-backend"],
      "sourceType": "oidc"
    },
    "escalationTokens": [],
    "sessionID": "session-001",
    "requestID": "req-001"
  }
}
```

**Expected OPA Response:**
```json
{
  "result": {
    "decision": "allow",
    "reason": "Read access allowed for developers",
    "requestID": "req-001"
  }
}
```

---

### Example 2: Filesystem Write (requires escalation for junior devs)

**Request to OPA:**
```json
{
  "input": {
    "serverName": "filesystem",
    "toolName": "write_file",
    "arguments": {
      "path": "/workspace/src/critical.go",
      "content": "package main\n// Modified code"
    },
    "userIdentity": {
      "userID": "charlie@example.com",
      "displayName": "Charlie Junior",
      "groups": ["developers", "junior"],
      "sourceType": "oidc"
    },
    "escalationTokens": [],
    "sessionID": "session-002",
    "requestID": "req-002"
  }
}
```

**Expected OPA Response:**
```json
{
  "result": {
    "decision": "escalate",
    "reason": "Junior developers require manager approval for write operations",
    "requestID": "req-002"
}
```

---

### Example 3: GitHub PR Creation (allowed with escalation token)

**Request to OPA:**
```json
{
  "input": {
    "serverName": "github",
    "toolName": "create_pull_request",
    "arguments": {
      "repo": "example-corp/production-app",
      "title": "Feature: Add new API endpoint",
      "base": "main",
      "head": "feature-123"
    },
    "userIdentity": {
      "userID": "charlie@example.com",
      "displayName": "Charlie Junior",
      "groups": ["developers", "junior"],
      "sourceType": "oidc"
    },
    "escalationTokens": [
      {
        "tokenID": "esc-pr-456",
        "raw": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
        "grantedBy": "bob.manager@example.com"
      }
    ],
    "sessionID": "session-003",
    "requestID": "req-003"
  }
}
```

**Expected OPA Response:**
```json
{
  "result": {
    "decision": "allow",
    "reason": "Escalation token validated for PR creation",
    "requestID": "req-003"
}
```

---

### Example 4: Database Access (deny for non-privileged users)

**Request to OPA:**
```json
{
  "input": {
    "serverName": "database",
    "toolName": "execute_query",
    "arguments": {
      "query": "SELECT * FROM users WHERE admin = true"
    },
    "userIdentity": {
      "userID": "eve@example.com",
      "displayName": "Eve External",
      "groups": ["contractors"],
      "sourceType": "oidc"
    },
    "escalationTokens": [],
    "sessionID": "session-004",
    "requestID": "req-004"
  }
}
```

**Expected OPA Response:**
```json
{
  "result": {
    "decision": "deny",
    "reason": "Database access not allowed for contractors",
    "requestID": "req-004"
  }
```

---

### Example 5: File Delete (requires specific path approval)

**Request to OPA:**
```json
{
  "input": {
    "serverName": "filesystem",
    "toolName": "delete_file",
    "arguments": {
      "path": "/workspace/config/production.yaml",
      "recursive": false
    },
    "userIdentity": {
      "userID": "alice@example.com",
      "displayName": "Alice Developer",
      "groups": ["developers", "senior"],
      "sourceType": "oidc"
    },
    "escalationTokens": [],
    "sessionID": "session-005",
    "requestID": "req-005"
  }
}
```

**Expected OPA Response:**
```json
{
  "result": {
    "decision": "escalate",
    "reason": "Deletion of production config requires DevOps approval",
    "requestID": "req-005"
  }
```

---

## Example OPA Policy Rules

Here are example Rego policies that implement the scenarios above.

### Basic Policy Structure

**File: `portcullis/policy.rego`**

```rego
package portcullis

import future.keywords.if
import future.keywords.in

# Default decision is deny (fail-safe)
default decision := {
    "decision": "deny",
    "reason": "No policy matched",
    "requestID": input.requestID
}

}

# Allow read access for developers
decision := {
    "decision": "allow",
    "reason": "Read access allowed for developers"
} if {
    input.toolName == "read_file"
    "developers" in input.userIdentity.groups
}

# Allow read_multiple_files for developers
decision := {
    "decision": "allow",
    "reason": "Read access allowed for developers"
} if {
    input.toolName == "read_multiple_files"
    "developers" in input.userIdentity.groups
}

# Allow list operations for developers
decision := {
    "decision": "allow",
    "reason": "List operations allowed for developers"
} if {
    input.toolName in ["list_directory", "list_allowed_directories", "directory_tree"]
    "developers" in input.userIdentity.groups
}

# Allow write for senior developers
decision := {
    "decision": "allow",
    "reason": "Write access granted to senior developers"
} if {
    input.toolName == "write_file"
    "senior" in input.userIdentity.groups
    "developers" in input.userIdentity.groups
}

# Junior developers need escalation for writes
decision := {
    "decision": "escalate",
    "reason": "Junior developers require manager approval for write operations"
} if {
    input.toolName == "write_file"
    "junior" in input.userIdentity.groups
    count(input.escalationTokens) == 0
}

# Allow writes if escalation token is present
decision := {
    "decision": "allow",
    "reason": "Escalation token validated for write operation"
} if {
    input.toolName == "write_file"
    "junior" in input.userIdentity.groups
    count(input.escalationTokens) > 0
    valid_escalation_token
}

# Deny database access for contractors
decision := {
    "decision": "deny",
    "reason": "Database access not allowed for contractors"
} if {
    input.serverName == "database"
    "contractors" in input.userIdentity.groups
}

# Allow database read for employees
decision := {
    "decision": "allow",
    "reason": "Database read access granted to employees"
} if {
    input.serverName == "database"
    input.toolName in ["query_read", "get_schema"]
    "employees" in input.userIdentity.groups
}

# Escalate for production config changes
decision := {
    "decision": "escalate",
    "reason": "Deletion of production config requires DevOps approval"
} if {
    input.toolName in ["delete_file", "move_file"]
    contains(input.arguments.path, "production")
    count(input.escalationTokens) == 0
}

# GitHub PR creation requires senior or escalation
decision := {
    "decision": "escalate",
    "reason": "Pull request creation requires manager approval"
} if {
    input.serverName == "github"
    input.toolName == "create_pull_request"
    not "senior" in input.userIdentity.groups
    count(input.escalationTokens) == 0
}

# Helper: Check if escalation token is valid
valid_escalation_token if {
    some token in input.escalationTokens
    # In production, validate JWT signature and expiration
    token.raw != ""
}

### Path-Based Policy

```rego
package portcullis

# Allow edits to docs by all developers
decision := {
    "decision": "allow",
    "reason": "Documentation edits allowed",
    "requestID": input.requestID
} if {
    input.toolName in ["write_file", "edit_file"]
    "developers" in input.userIdentity.groups
    startswith(input.arguments.path, "/workspace/docs/")
}

# Deny edits to .git directory
decision := {
    "decision": "deny",
    "reason": "Direct .git manipulation not allowed",
    "requestID": input.requestID
} if {
    input.toolName in ["write_file", "delete_file", "move_file"]
    contains(input.arguments.path, ".git/")
}
} if {
    input.toolName in ["write_file", "edit_file"]
    "developers" in input.userIdentity.groups
    startswith(input.arguments.path, "/workspace/docs/")
}

# Deny edits to .git directory
decision := {
    "decision": "deny",
    "reason": "Direct .git manipulation not allowed"
} if {
    input.toolName in ["write_file", "delete_file", "move_file"]
    contains(input.arguments.path, ".git/")
}

# Escalate for infrastructure changes
decision := {
    "decision": "escalate",
    "reason": "Infrastructure changes require SRE approval"
# Deny destructive operations outside business hours
decision := {
    "decision": "escalate",
    "reason": "Destructive operations outside business hours require approval",
    "requestID": input.requestID
} if {
    input.toolName in ["delete_file", "drop_table", "delete_resource"]
    not business_hours
}

business_hours if {
    # Get current hour (0-23) and day of week (0-6, 0=Sunday)
    now := time.now_ns()
    [_, hour, _] := time.clock([now, "America/New_York"])
    [_, _, day] := time.date([now, "America/New_York"])
    
    # Monday-Friday (1-5)
    day >= 1
    day <= 5
    
    # 9 AM - 5 PM
    hour >= 9
}
```

---

## Testing Policies with OPA

### Running OPA Locally

```bash
# Install OPA
# macOS: brew install opa
# Linux: see https://www.openpolicyagent.org/docs/latest/#running-opa

# Start OPA server
opa run --server --addr localhost:8181

# Load policy
curl -X PUT http://localhost:8181/v1/policies/portcullis \
  --data-binary @policy.rego

# Test a decision
curl -X POST http://localhost:8181/v1/data/portcullis/decision \
  -H 'Content-Type: application/json' \
  -d @test-request.json
```

### Example Test Request File

**File: `test-request.json`**

```json
{
  "input": {
    "serverName": "filesystem",
    "toolName": "write_file",
    "arguments": {
      "path": "/workspace/src/main.go",
      "content": "package main"
    },
    "userIdentity": {
      "userID": "alice@example.com",
      "displayName": "Alice Developer",
      "groups": ["developers", "senior"],
      "sourceType": "oidc"
    },
    "escalationTokens": [],
    "sessionID": "test-session-001",
    "requestID": "test-req-001"
  }
}
```

### Unit Testing Policies

**File: `policy_test.rego`**

```rego
package portcullis

test_read_allowed_for_developers if {
    result := decision with input as {
        "toolName": "read_file",
        "userIdentity": {"groups": ["developers"]},
        "escalationTokens": [],
        "sessionID": "test-1",
        "requestID": "req-1"
    }
    result.decision == "allow"
}

test_write_denied_for_contractors if {
    result := decision with input as {
        "toolName": "write_file",
        "serverName": "filesystem",
        "userIdentity": {"groups": ["contractors"]},
        "escalationTokens": [],
        "sessionID": "test-2",
        "requestID": "req-2"
    }
    result.decision == "deny"
}

test_junior_needs_escalation if {
    result := decision with input as {
        "toolName": "write_file",
        "userIdentity": {"groups": ["developers", "junior"]},
        "escalationTokens": [],
        "sessionID": "test-3",
        "requestID": "req-3"
    }
    result.decision == "escalate"
}

test_escalation_token_allows_junior if {
    result := decision with input as {
        "toolName": "write_file",
        "userIdentity": {"groups": ["developers", "junior"]},
        "escalationTokens": [
            {"tokenID": "esc-1", "raw": "valid-token", "grantedBy": "manager"}
        ],
        "sessionID": "test-4",
        "requestID": "req-4"
    }
    result.decision == "allow"
}
```

Run tests with:
```bash
opa test policy.rego policy_test.rego -v
```

---

## Integration with Portcullis-Keep

In your `keep.yaml` config:

```yaml
pdp:
  type: "opa"
  endpoint: "http://localhost:8181/v1/data/portcullis/decision"
```

Portcullis-keep will:
1. Wrap the `EnrichedMCPRequest` in `{"input": {...}}`
2. POST to the OPA endpoint
3. Parse the `result.decision` and `result.reason`
4. Execute the appropriate action (allow → route to MCP server, deny → send rejection notice back to Portcullis-gate, escalate → submit request to workflow and send escalation notice back to Portcullis-gate)

---

## Policy Design Tips

1. **Default Deny**: Always start with `default decision := {"decision": "deny", ...}`
2. **Explicit Allow**: Write specific rules for allowed operations
3. **Escalation for Uncertainty**: There should be clear, well-defined scenarios for when escalation is allowed
4. **Audit Everything**: Always include descriptive reasons for deny and escalate
5. **Test Thoroughly**: Use `opa test` to validate your policies
6. **Group-Based**: Leverage `userIdentity.groups` for role-based access
7. **Context Matters**: Use `serverName`, `toolName`, and `arguments` together
8. **Validate Tokens**: In production, validate escalation token signatures and expiration
9. **Traceability**: Portcullis uses `requestID` for audit trails, so you don't need to generate separate audit IDs
---

## Additional Resources

- [OPA Documentation](https://www.openpolicyagent.org/docs/latest/)
- [Rego Language Guide](https://www.openpolicyagent.org/docs/latest/policy-language/)
- [OPA Playground](https://play.openpolicyagent.org/) - Test policies online
- [OPA Best Practices](https://www.openpolicyagent.org/docs/latest/policy-performance/)
