# OPA Policy Examples for Portcullis

Portcullis enforces that every MCP tool call is evaluated by a Policy Decision
Point (PDP) before execution. **How you write that policy is entirely up to your
organization.** Portcullis ships two example Rego implementations to illustrate
the options — operators are expected to write their own policy suited to their
environment, groups, and tools.


| Example file | Approach |
|---|---|
| `policies/rego/portcullis/custom/decision.rego` | Explicit Rego rules — readable, auditable, easily reviewed by security teams |
| `policies/rego/portcullis/tabular/decision.rego` | Table-driven — rules read from `data.portcullis.mcp`; populate via Data API, S3 bundles, LDAP, or any OPA data source |

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

## What Portcullis Sends to the PDP

Portcullis-keep sends an AuthorizationRequest, along with some correlation data to the PDP. For OPA, the AuthorizationRequest is wrapped in an `input` envelope.

The AuthorizationRequest uses the standard authorization elements:

* Principal: Information about the user making the request
* Action:  which MCP and tool is being used
* Resource: the details of the request that the AI agent wishes to send to the MCP .  For convenience, the URL elements of these requests are disassembled for security and ease of use.
* Context: any escalation tokens associated with the user session

Basically, for each MCP request that arrives at Portcullis-Keep, the Keep forwards this request to the PDP to answer the following question: "on behalf of Principal, the AI agent wishes to send <Request> to MCP <X>, tool <Y>.  Is this allowed, denied, or does it require escalated privilege?" 


All field names use **snake_case**.

```json
{
  "input": {
        {
          "authorization_request": {                
            "action": {
                "tool_name": "fetch",
                "service" : "fetch"
            },
            "resource": {
                "arguments": {
                    "raw": "https://styra.com",
                    "scheme": "https",
                    "host": "styra.com",
                    "port": "",
                    "path": "",
                    "query": ""
                }
            },
            "principal": {
                "user_id": "alice@example.com",
                "email": "alice@example.com",
                "display_name": "Alice Developer",
                "groups": ["developer", "internal-api-users"],
                "roles": ["api-consumer"],
                "department": "engineering",
                "auth_method": ["pwd", "mfa"],
                "token_expiry": 1741651200,
                "source_type": "oidc"
            },
            "context": {
                "escalation_tokens": [
                ]
            }
          },
            "session_id": "sess-abc123",
            "request_id": "req-def456"
        }
}
```

OPA would return a response in this format:

```json
{
  "result": {
    "decision": "allow",
    "reason": "user is authorized to perform this action",
    "request_id": "req-xyz789"
  }
}
```

Other PDPs might not need the `result` element, but that's a minor difference.

The `request_id` is echoed from the input for audit correlation. If the request_id isn't available, the PDP should
respond with a 0

---

## Example: Hand-written Rego Rules

`policies/rego/portcullis/custom/decision.rego` shows policy written as explicit Rego rules.
This approach is easy to read, diff, and audit — a security reviewer can read the
file and understand exactly what is permitted without knowing OPA internals.

Snippet from the example:

```rego

response_list contains 
				{ "decision":"deny", 
				  "reason":"Denied - MCP is not in scope", 
				  "request_id": request_id} if {

   not input.service in ["portcullis-localfs", "mock-enterprise-api", "fetch"]
}


response_list contains 
				{ "decision":"escalate", 
				  "reason":"This request requires escalated privilege", 
				  "request_id": request_id} if {

   action.service in ["portcullis-localfs"]
   action.tool_name in ["write_file"]
   some prefix in [ "C:\\Program Files", "C:\\Program Files (x86)" , "/var" ]
 		 startswith(resource.arguments.path, prefix)
	
   not escalate.escalation_grant_matches_group_service_tool_and_request_args(
			escalation_grant_list,
			["*"],
			action.service,
			action.tool_name,
			resource.arguments)

}

```

These are just examples! You can write your own, any way you want, as long as you handle the input and
output documents in a consistent way.


---

## Example: Table-driven Policy

`policies/rego/portcullis/tabular/decision.rego` shows policy written as a **generic table evaluator**.
It reads policy rules from `data.portcullis.mcp` — an array of rule objects.
The Rego itself never changes; only the data changes — which means policy can be
managed/changed by any system that can write the `data.json` file in a way that the OPA can retrieve
(such as embedded, from a cloud bucket, from a database query, etc)

look at `policies/rego/data.json` for the example we implemented as a Proof of Concept

---

## Loading Policy Data into OPA
We assume that the reader is already familiar with how to use OPA to manage policy.  If not, there are
lots of resources online. The key reason we believe that policy should be managed this way are:
1) the policy logic is typically stored in a source code repository, allowing for formal change management
2) OPAs generate decision records for every request, which is critical for auditing
3) Rego is well-established in the policy ecosystem, and quite suitable for the potentially very complex rules that might govern AI agent access
4) OPA is scalable, fast and very robust, trusted for mission-critical policy decisions in very large organizations


---

## Escalation Token JWT Design

Escalation tokens are signed JWTs that an approver (user, manager or workflow system)
creates out-of-band. The user adds the JWT to their Portcullis-Gate token store via the management UI;
the Gate attaches it to every subsequent MCP request until it expires. Portcullis-Keep dutifully sends
the set of escalation tokens on to the PDP, and those tokens are used to determine if an otherwise denied
MCP request should be approved. 

The PDP is the sole authority on whether a token is valid and covers the request.
Portcullis-Gate only prunes expired tokens on load.

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
    "services":    ["filesystem"],
    "groups" :     ["admin"],
    "arg_restrictions": [
       { "type":"prefix", "key_path": "path", "data": "/workspace/feature-x/", "required":true }
    ],
    "reason":      "Sprint 42 feature branch work"
  }
}
```

| Claim | Description |
|---|---|
| `sub` | User the grant is for — must match `input.user_identity.user_id` |
| `jti` | Unique token ID — enables revocation via OPA data |
| `exp` | Hard expiry — enforced automatically by `io.jwt.decode_verify` |
| `portcullis.tools` | Permitted tool names |
| `portcullis.servers` | Permitted server names |
| `portcullis.groups` | Granted group access |
| `portcullis.arg_restrictions` | *(optional)* Provides additional nuance to what specific arguments are allowed |

When a valid escalation token covers the request, any `escalate` rules that
would otherwise fire are suppressed, and the PDP returns `allow` instead.

### Signature verification

Configure exactly one of the following in your OPA `data.json`.  Note that the proof-of-concept implementation
uses a shared secret, but switching the Asymmetric keys is straightfoward.  In the `data.json` we are using
for the PoC, the shared secret is under the `config.escalation_secret` path.

If you wish to use Asymmetric keys, you will need to modify the logic to include the URL for the public key so OPA/Rego can validate the signature.  

**Option B — Asymmetric keys via JWKS (RS256/ES256, production-recommended):**
```json
{ "config": { "escalation_jwks_url": "https://keys.internal.example.com/.well-known/jwks.json" } }
```

---

## Testing Policies with OPA

### Running OPA locally

In our example implementation, we use the open source Rego testing tool `raygun` (https://github.com/paclabsnet/raygun) for testing. It automatically handles firing up OPA, ending requests to it, and processing the results.

If you want to test by hand:

```bash
cd policies/rego
# build the bundle.tar.gz
./build.sh
# Start OPA with the policy Rego and initial data
opa run --server -b bundle.tar.gz

# Test a decision
curl -s -X POST http://localhost:8181/v1/data/portcullis/tabular/decision \
  -H 'Content-Type: application/json' \
  -d @test-request.json | jq .
```


---

## Extending Either Example

Because `deny`, `escalate`, and `allow` are incremental rules (sets or
booleans contributed to by multiple definitions), any file in the same OPA package
can add to them without modifying the base policy file. This works with both the
hand-written and table-driven examples.

For example, to add a business-hours restriction across all policies in the tabular scenario, create a
separate file in the same package:

```rego
package portcullis.tabular

import rego.v1

# non-business-hours request
response_list contains { "decision" : "deny", 
			"reason" : "no access during non-business hours: (Mon–Fri 08:00–18:00 UTC)", 
			"request_id" : request_id } if {
   now := time.now_ns()
   day  := time.weekday(now)   # 0=Sunday, 6=Saturday
   hour := time.clock(now)[0]
   day in [0,6]
   hour < 8
   hour > 18
}

```

the file would automatically be included in the bundle after `./build.sh` is run

