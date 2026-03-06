# EXAMPLE POLICY — Table-driven evaluation
#
# This is one example of how an operator might write Portcullis policy.
# Rules are evaluated against a policy table stored in data.portcullis.policies,
# which OPA can load from its Data API, bundles (S3, GCS, HTTP), or plugins.
# Neither approach is required — use whatever best fits your organization.
#
# See also: custom/decision.rego for explicit rego rules alternative.
#

#
#  for any given table entry, there are three evaluation sections:
#  allow, escalate, and deny
#
#  here's my thinking:
#  deny is absolute - there is no escalation token that can override a deny,
#  so if the deny rule says "the agent can't write to ~/.ssh", it doesn't matter if
#  the agent has an escalation token granting it access to ~/.ssh . 
#
#  allow comes next - if the user request matches the allow criteria, then it is
#  allowed.  This doesn't check for escalation tokens either
#
#  finally, there's the escalate case.  If you get to this case, and you have no
#  escalation tokens that allow you to pass the escalate restrictions, then the
#  agent is not allowed to do the thing, and we return "escalate", and we provide
#  details on how to meet the necessary criteria
#
#  if you get to this case, and you have an escalation token that does allow you
#  to pass the escalate restrictions, we return "allow", because you've been 
#  granted the appropriate access
#
#  
#  this is probably a little confusing, so let's use a simple example
#  We're trying to write policy that protects a database MCP from rogue agent SQL commands
#  if the SQL command starts with "SELECT FROM" is always allowed
#  if the command starts with "DROP TABLE" it's a deny
#  If the command starts with "CREATE TABLE" it is an escalate
# 
#  You're working with the agent, and it decides it wants to create a table called NATIONS
#  the policy rule returns "escalate"
#
#  You get with the DBA, and they grant you an escalation token that includes the specific
#  command "CREATE TABLE NATIONS"
#
#  You add that token to your session, and tell the agent to proceed.  The agent, however
#  has gotten distracted, and this time it creates the command "CREATE TABLE NATION_STATE"
#  This won't be approved by policy, because the policy specifically says "CREATE TABLE NATIONS",
#  so it would fail and potentially start another escalation process
#
#  But you can yell at the agent and tell it to use NATIONS.  So it tries again, and uses
#  the correct SQL "CREATE TABLE NATIONS"
#
#  now, the escalate rules have been honored, so the agent's MCP request is now passed on
#  to the database MCP
#

package portcullis.tabular

import rego.v1
import data.portcullis.util

# ============================================================================
# DEFAULT — fail-safe deny
# ============================================================================

default decision := {
	"decision":   "deny",
	"reason":     "no policy matched, default deny",
	"request_id": 0
}


#
# Evaluate the request by looking up 
# data.portcullis.mcp.<service>.<tool>
# If there's nothing there, automatic deny
# If there's a deny section, process that first.  If the criteria for deny are
# met, it's a deny
# Evaluate the allow section next. If the criteria are met, it's an allow
# If the allow criteria ISN'T met, we get a fun scenario:
#  a) if there's no escalate section, it's a deny
#  b) if there is an escalate section, process the criteria. The result should
#     either be 'escalate' or 'allow'
#



# ============================================================================
# ESCALATION TOKEN VALIDATION
#
# Escalation tokens are signed JWTs issued by an approver (human or workflow
# system) and carried by the user in their token store.  The PDP is the
# authority on whether a token is valid and covers the current request.
#
#  Here's an example:
#
# {
#  "sub": "alice@example.com",
#  "jti": "550e8400-e29b-41d4-a716-446655440000",
#  "iss": "portcullis-approver",
#  "iat": 1700000000,
#  "exp": 1700086400,
#  "granted_by": "bob.manager@example.com",
#  "portcullis": {
#    "tools":       ["write_file", "edit_file"],
#    "services":    ["filesystem"],
#    "groups" :     ["admin"],
#    "arg_restrictions": [
#       { "type":"prefix", "key_path": "path", "data": "/workspace/feature-x/", "required":true }
#    ],
#    "reason":      "Sprint 42 feature branch work"
#  }
# }
# Signature verification is configured via OPA data:
#   data.portcullis.config.escalation_secret
#
# of these, the portcullis.tools, portcullis.services, portcullis.groups are all required
# 
# portcullis.arg_restrictions is recommended, but not required. This allows for fine-grained
# permission grants, for example for specific filepaths, or specific SQL commands, things
# like that.  This is helpful in preventing the AI agent from hallucinating and attempting
# to perform actions with the token that were different than the ones it wanted to do
# when the escalation was requested
#
#
# ============================================================================


#
# The input request will look something like:
# 
# {
#  "input": {
#    "service": "portcullis-localfs",
#    "tool_name": "write_file",
#    "arguments": {
#      "path": "/workspace/src/main.go",
#      "content": "package main\n..."
#    },
#    "user_identity": {
#      "user_id": "alice@example.com",
#      "display_name": "Alice Developer",
#      "groups": ["developers", "team-backend"],
#      "source_type": "oidc",
#      "raw_token": "eyJhbGc..."
#    },
#    "escalation_tokens": [
#      {
#        "token_id": "esc-12345",
#        "raw": "eyJhbGc...",
#        "granted_by": "bob.manager@example.com"
#      }
#    ],
#    "session_id": "session-abc123",
#    "request_id": "req-xyz789"
#  }
# }


response_list contains { "decision":   "deny",	
			  "reason":  "invalid input request",
			  "request_id": input.request_id } if {

				not util.is_valid_request( input )

			  }


rules_section := util.traverse_json_2(data.portcullis.mcp, [input.service, input.tool_name], null)

response_list contains { "decision":   "deny",	
			  "reason":  sprintf("no policy rules found for mcp: %s, tool: %s", [input.service, input.tool_name]),
			  "request_id": input.request_id } if {

				rules_section == null
			  }

response_list contains { "decision" : "deny", 
			  "reason" : "Denied by rule",
			  "request_id": input.request_id } if {

				print("#DEBUG: rules_section: ", rules_section)

				not rules_section.deny == null
				does_request_meet_criteria_no_escalation( input, rules_section.deny )

			  }


response_list contains { "decision" : "allow",
			  "reason" : "Allowed by rule",
			  "request_id" : input.request_id } if {

				not rules_section.allow == null
				does_request_meet_criteria_no_escalation( input, rules_section.allow )

			  }


response_list contains { "decision" : "allow",
			  "reason" : "Allowed by escalation token",
			  "request_id" : input.request_id } if {

				not rules_section.escalate == null
				does_request_meet_criteria_with_escalation( 
						input, 
						rules_section.escalate, 
						input.service, 
						input.tool_name, 
						data.config.escalation_secret )

			  }

response_list contains {
				"decision" : "escalate",
			  	"reason" : "Request is not approved, but can be escalated",
			  	"request_id" : input.request_id } if {

					not rules_section.escalate == null
					not does_request_meet_criteria_with_escalation( 
							input, 
							rules_section.escalate, 
							input.service, 
							input.tool_name, 
							data.config.escalation_secret )
				}


# no response, deny
decision := { "decision" : "deny", 
				"reason" : "no matching rule found", 
				"request_id" : input.request_id } if {
					count(response_list) == 0
				}

# only one response, return it
#decision := single_response if { 
#				count(response_list) == 1
#				some x in response_list
#					single_response := x
#			}

#
# multiple responses?  handle the scenarios
#

deny_list := [ x | 
				some x in response_list
					x.decision == "deny"
			]

allow_list := [ x | 
				some x in response_list
					x.decision == "allow"
			]


escalate_list := [ x | 
				some x in response_list
					x.decision == "escalate"
			]			

decision := deny_result if {
	count(deny_list) > 0
	deny_result := deny_list[0]
}


decision := escalate_result if {
	count(deny_list) == 0
	# count(allow_list) == 0
	count(escalate_list) > 0
	escalate_result := escalate_list[0]
}


decision := allow_list if {
	count(deny_list) == 0
	count(escalate_list) == 0
	count(allow_list) > 0
	allow_result := allow_list[0]
}







#
# compare the request to the rule criteria
#
# these will typically be rules around group membership and
# the presence or absence of key information in the request
#
does_request_meet_criteria_no_escalation( request, rules ) := true if {

	print("#DEBUG: does_request_meet_criteria_no_escalation: ", request, " ", rules)

	util.request_matches_criteria( request, rules )

} else := false


does_request_meet_criteria_with_escalation( request, rules, service, tool_name, jwt_secret ) := true if {

	# if we match the core criteria, we're good
    util.request_matches_criteria( request, rules)

} else := does_request_meet_criteria_escalation_only( request, rules, service, tool_name, jwt_secret) 



does_request_meet_criteria_escalation_only( request, rules, service, tool_name, jwt_secret) := true if {

	util.request_matches_escalation_criteria( request, rules, service, tool_name, jwt_secret)

} else := false



# verify_options := opts if {
# 	data.portcullis.escalation_secret != ""
# 	opts := {
# 		"secret": data.portcullis.escalation_secret,
# 		"iss":    "portcullis-approver",
# 	}
# } else := opts if {
# 	data.portcullis.escalation_jwks_url != ""
# 	opts := {
# 		"jwks_url": data.portcullis.escalation_jwks_url,
# 		"iss":      "portcullis-approver",
# 	}
# }

# # valid_escalation_for_request is true when at least one escalation token
# # passes signature verification and covers the current request.
# valid_escalation_for_request if {
# 	some token in input.escalation_tokens
# 	[valid, _, payload] := io.jwt.decode_verify(token.raw, verify_options)
# 	valid == true

# 	# Token must be issued for this specific user (prevents token sharing).
# 	payload.sub == input.user_identity.user_id

# 	pc := payload.portcullis
# 	server_covered(pc)
# 	tool_covered(pc)
# 	path_covered(pc)
# }

# server_covered(pc) if { pc.servers == ["*"] }
# server_covered(pc) if { input.server_name in pc.servers }

# tool_covered(pc) if { pc.tools == ["*"] }
# tool_covered(pc) if { input.tool_name in pc.tools }

# path_covered(pc) if { not pc.path_prefix }
# path_covered(pc) if {
# 	pc.path_prefix
# 	startswith(input.arguments.path, pc.path_prefix)
# }

# # ============================================================================
# # POLICY TABLE EVALUATION
# #
# # Reads from data.portcullis.policies — an array of policy rule objects.
# # Rules are evaluated for every request; all matching deny rules accumulate
# # into the deny set, all matching escalate rules into the escalate set.
# #
# # Rule schema:
# #   id:          string  — identifier for audit / debugging
# #   server:      string  — MCP server name, or "*" for any
# #   tools:       [string] — tool names this rule applies to (omit = any tool)
# #   groups:      [string] — user must be in at least one group
# #   action:      "allow" | "deny" | "escalate"
# #   reason:      string  — returned to the caller on deny/escalate
# #   path_prefix: string  — (optional) restrict to paths with this prefix
# #
# # Data can be loaded via:
# #   - OPA Data API:  PUT /v1/data/portcullis/policies
# #   - OPA Bundles:   bundle from S3, GCS, HTTP, etc.
# #   - OPA plugins:   LDAP, database, Consul, etc.
# # ============================================================================

# rule_matches(rule) if {
# 	server_matches_rule(rule)
# 	tool_matches_rule(rule)
# 	group_matches_rule(rule)
# 	path_matches_rule(rule)
# }

# server_matches_rule(rule) if { rule.server == "*" }
# server_matches_rule(rule) if { rule.server == input.server_name }

# # No tools constraint means the rule applies to any tool.
# tool_matches_rule(rule) if { not rule.tools }
# tool_matches_rule(rule) if { input.tool_name in rule.tools }

# # User must be in at least one of the listed groups.
# group_matches_rule(rule) if {
# 	some group in rule.groups
# 	group in input.user_identity.groups
# }

# # No path_prefix constraint means any path is acceptable.
# path_matches_rule(rule) if { not rule.path_prefix }
# path_matches_rule(rule) if {
# 	rule.path_prefix
# 	startswith(input.arguments.path, rule.path_prefix)
# }

# # Collect all matching deny reasons.
# deny contains reason if {
# 	some rule in data.portcullis.policies
# 	rule.action == "deny"
# 	rule_matches(rule)
# 	reason := rule.reason
# }

# # Collect all matching escalate reasons.
# # Suppressed when a valid escalation token covers the request, allowing
# # the request to fall through to the allow decision below.
# escalate contains reason if {
# 	some rule in data.portcullis.policies
# 	rule.action == "escalate"
# 	rule_matches(rule)
# 	not valid_escalation_for_request
# 	reason := rule.reason
# }

# # request_permitted is true when a policy rule explicitly allows access,
# # or a valid escalation token covers the request.
# request_permitted if {
# 	some rule in data.portcullis.policies
# 	rule.action == "allow"
# 	rule_matches(rule)
# }

# request_permitted if { valid_escalation_for_request }

# # ============================================================================
# # FINAL DECISION LOGIC
# # Priority: deny > escalate > allow > default deny
# # ============================================================================

# # Deny if any deny rule matched.
# decision := {
# 	"decision":   "deny",
# 	"reason":     reason,
# 	"request_id": input.request_id,
# } if {
# 	count(deny) > 0
# 	reason := concat("; ", deny)
# }

# # Escalate if no denials but at least one escalation rule matched.
# decision := {
# 	"decision":   "escalate",
# 	"reason":     reason,
# 	"request_id": input.request_id,
# } if {
# 	count(deny) == 0
# 	count(escalate) > 0
# 	reason := concat("; ", escalate)
# }

# # Allow if no denials, no escalations, and the request is permitted.
# decision := {
# 	"decision":   "allow",
# 	"reason":     "user is authorized to perform this action",
# 	"request_id": input.request_id,
# } if {
# 	count(deny) == 0
# 	count(escalate) == 0
# 	request_permitted
# }
