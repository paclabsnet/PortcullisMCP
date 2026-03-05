# EXAMPLE POLICY — Hand-written Rego rules
#
# This is one example of how an operator might write Portcullis policy.
# Rules are written explicitly in Rego rather than evaluated from a data table.
# Neither approach is required — use whatever best fits your organization.
#
# To use this file instead of decision.rego:
#   opa run --server --addr localhost:8181 \
#     policies/decision-handwritten.rego \
#     --data <(echo '{"portcullis":{"escalation_secret":"your-secret"}}')
#
# The PDP endpoint Portcullis-keep calls is always:
#   POST /v1/data/portcullis/decision

package portcullis.custom

import rego.v1

# ============================================================================
# DEFAULT — fail-safe deny
# ============================================================================

default decision := {
	"decision":   "deny",
	"reason":     "policy processing error, default deny",
	"request_id": input.request_id,
}

# ============================================================================
# ESCALATION TOKEN VALIDATION
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

valid_escalation_for_request if {
	some token in input.escalation_tokens
	[valid, _, payload] := io.jwt.decode_verify(token.raw, verify_options)
	valid == true
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
# DENY RULES
# Each rule adds a reason to the deny set; any match = deny.
# ============================================================================

# Block access to .git directories.
deny contains "access to .git directories is forbidden" if {
	input.arguments.path
	contains(input.arguments.path, "/.git/")
}

deny contains "access to .git directories is forbidden" if {
	input.arguments.path
	startswith(input.arguments.path, ".git/")
}

# Block access to the Portcullis config directory.
deny contains "access to .portcullis is forbidden" if {
	input.arguments.path
	contains(input.arguments.path, "/.portcullis")
}

# Contractors may not access the database at all.
deny contains "contractors may not access the database" if {
	input.server_name == "database"
	"contractors" in input.user_identity.groups
}

# Only admins may delete orders.
deny contains "deleting orders requires admin group membership" if {
	input.tool_name == "delete_order"
	input.server_name == "mock-enterprise-api"
	not "admin" in input.user_identity.groups
}

# ============================================================================
# ESCALATION RULES
# Each rule fires only when no valid escalation token covers the request.
# A valid token suppresses the escalation and the request falls through to allow.
# ============================================================================

# Filesystem write operations require manager approval (non-admins).
escalate contains "write operations require manager approval" if {
	input.tool_name in ["write_file", "edit_file", "delete_file", "move_file", "copy_file"]
	input.server_name == "filesystem"
	not "admin" in input.user_identity.groups
	not valid_escalation_for_request
}

# Order status changes require manager approval (non-admins).
escalate contains "order updates require manager approval" if {
	input.tool_name == "update_order_status"
	input.server_name == "mock-enterprise-api"
	not "admin" in input.user_identity.groups
	not valid_escalation_for_request
}

# ============================================================================
# ALLOW RULES
# Explicit rules for what is permitted.
# ============================================================================

# Developers and analysts may read from the filesystem.
allow_matched if {
	input.server_name == "filesystem"
	input.tool_name in ["read_text_file", "list_directory", "directory_tree",
	                    "search_files", "search_within_files"]
	some group in ["developers", "analysts", "contractors"]
	group in input.user_identity.groups
}

# Developers and analysts may query the database.
allow_matched if {
	input.server_name == "database"
	input.tool_name == "execute_query"
	some group in ["developers", "analysts"]
	group in input.user_identity.groups
}

# Any authenticated user may call read-only enterprise API tools.
allow_matched if {
	input.server_name == "mock-enterprise-api"
	input.tool_name in ["get_order", "list_orders", "get_customer"]
}

# Request is permitted via a valid escalation token.
allow_matched if { valid_escalation_for_request }

# ============================================================================
# FINAL DECISION LOGIC
# Priority: deny > escalate > allow > default deny
# ============================================================================

decision := {
	"decision":   "deny",
	"reason":     reason,
	"request_id": input.request_id,
} if {
	count(deny) > 0
	reason := concat("; ", deny)
}

decision := {
	"decision":   "escalate",
	"reason":     reason,
	"request_id": input.request_id,
} if {
	count(deny) == 0
	count(escalate) > 0
	reason := concat("; ", escalate)
}

decision := {
	"decision":   "allow",
	"reason":     "user is authorized to perform this action",
	"request_id": input.request_id,
} if {
	count(deny) == 0
	count(escalate) == 0
	allow_matched
}
