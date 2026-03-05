# EXAMPLE POLICY — Table-driven evaluation
#
# This is one example of how an operator might write Portcullis policy.
# Rules are evaluated against a policy table stored in data.portcullis.policies,
# which OPA can load from its Data API, bundles (S3, GCS, HTTP), or plugins.
# Neither approach is required — use whatever best fits your organization.
#
# See also: policies/decision-handwritten.rego for an explicit-rules alternative.
#
# To use this file:
#   opa run --server --addr localhost:8181 \
#     policies/decision.rego \
#     --data policy-data.json

package portcullis.tabular

import rego.v1

# ============================================================================
# DEFAULT — fail-safe deny
# ============================================================================

default decision := {
	"decision":   "deny",
	"reason":     "no policy matched, default deny",
	"request_id": input.request_id,
}

# ============================================================================
# ESCALATION TOKEN VALIDATION
#
# Escalation tokens are signed JWTs issued by an approver (human or workflow
# system) and carried by the user in their token store.  The PDP is the
# authority on whether a token is valid and covers the current request.
#
# Required JWT claims:
#   sub           — must match input.user_identity.user_id
#   exp           — hard expiry (enforced by io.jwt.decode_verify)
#   iss           — must be "portcullis-approver"
#   portcullis    — object with:
#     tools       — array of permitted tool names, or ["*"] for any
#     servers     — array of permitted server names, or ["*"] for any
#     path_prefix — (optional) restrict to paths with this prefix
#
# Signature verification is configured via OPA data:
#   Option A (HS256): data.portcullis.escalation_secret
#   Option B (RS256/ES256 with JWKS): data.portcullis.escalation_jwks_url
# ============================================================================

verify_options := opts if {
	data.portcullis.escalation_secret != ""
	opts := {
		"secret": data.portcullis.escalation_secret,
		"iss":    "portcullis-approver",
	}
} else := opts if {
	data.portcullis.escalation_jwks_url != ""
	opts := {
		"jwks_url": data.portcullis.escalation_jwks_url,
		"iss":      "portcullis-approver",
	}
}

# valid_escalation_for_request is true when at least one escalation token
# passes signature verification and covers the current request.
valid_escalation_for_request if {
	some token in input.escalation_tokens
	[valid, _, payload] := io.jwt.decode_verify(token.raw, verify_options)
	valid == true

	# Token must be issued for this specific user (prevents token sharing).
	payload.sub == input.user_identity.user_id

	pc := payload.portcullis
	server_covered(pc)
	tool_covered(pc)
	path_covered(pc)
}

server_covered(pc) if { pc.servers == ["*"] }
server_covered(pc) if { input.server_name in pc.servers }

tool_covered(pc) if { pc.tools == ["*"] }
tool_covered(pc) if { input.tool_name in pc.tools }

path_covered(pc) if { not pc.path_prefix }
path_covered(pc) if {
	pc.path_prefix
	startswith(input.arguments.path, pc.path_prefix)
}

# ============================================================================
# POLICY TABLE EVALUATION
#
# Reads from data.portcullis.policies — an array of policy rule objects.
# Rules are evaluated for every request; all matching deny rules accumulate
# into the deny set, all matching escalate rules into the escalate set.
#
# Rule schema:
#   id:          string  — identifier for audit / debugging
#   server:      string  — MCP server name, or "*" for any
#   tools:       [string] — tool names this rule applies to (omit = any tool)
#   groups:      [string] — user must be in at least one group
#   action:      "allow" | "deny" | "escalate"
#   reason:      string  — returned to the caller on deny/escalate
#   path_prefix: string  — (optional) restrict to paths with this prefix
#
# Data can be loaded via:
#   - OPA Data API:  PUT /v1/data/portcullis/policies
#   - OPA Bundles:   bundle from S3, GCS, HTTP, etc.
#   - OPA plugins:   LDAP, database, Consul, etc.
# ============================================================================

rule_matches(rule) if {
	server_matches_rule(rule)
	tool_matches_rule(rule)
	group_matches_rule(rule)
	path_matches_rule(rule)
}

server_matches_rule(rule) if { rule.server == "*" }
server_matches_rule(rule) if { rule.server == input.server_name }

# No tools constraint means the rule applies to any tool.
tool_matches_rule(rule) if { not rule.tools }
tool_matches_rule(rule) if { input.tool_name in rule.tools }

# User must be in at least one of the listed groups.
group_matches_rule(rule) if {
	some group in rule.groups
	group in input.user_identity.groups
}

# No path_prefix constraint means any path is acceptable.
path_matches_rule(rule) if { not rule.path_prefix }
path_matches_rule(rule) if {
	rule.path_prefix
	startswith(input.arguments.path, rule.path_prefix)
}

# Collect all matching deny reasons.
deny contains reason if {
	some rule in data.portcullis.policies
	rule.action == "deny"
	rule_matches(rule)
	reason := rule.reason
}

# Collect all matching escalate reasons.
# Suppressed when a valid escalation token covers the request, allowing
# the request to fall through to the allow decision below.
escalate contains reason if {
	some rule in data.portcullis.policies
	rule.action == "escalate"
	rule_matches(rule)
	not valid_escalation_for_request
	reason := rule.reason
}

# request_permitted is true when a policy rule explicitly allows access,
# or a valid escalation token covers the request.
request_permitted if {
	some rule in data.portcullis.policies
	rule.action == "allow"
	rule_matches(rule)
}

request_permitted if { valid_escalation_for_request }

# ============================================================================
# FINAL DECISION LOGIC
# Priority: deny > escalate > allow > default deny
# ============================================================================

# Deny if any deny rule matched.
decision := {
	"decision":   "deny",
	"reason":     reason,
	"request_id": input.request_id,
} if {
	count(deny) > 0
	reason := concat("; ", deny)
}

# Escalate if no denials but at least one escalation rule matched.
decision := {
	"decision":   "escalate",
	"reason":     reason,
	"request_id": input.request_id,
} if {
	count(deny) == 0
	count(escalate) > 0
	reason := concat("; ", escalate)
}

# Allow if no denials, no escalations, and the request is permitted.
decision := {
	"decision":   "allow",
	"reason":     "user is authorized to perform this action",
	"request_id": input.request_id,
} if {
	count(deny) == 0
	count(escalate) == 0
	request_permitted
}
