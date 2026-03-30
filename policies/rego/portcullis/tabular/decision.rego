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
import data.portcullis.allowdeny
import data.portcullis.escalate
import data.portcullis.digest
import data.portcullis.custom

# ============================================================================
# DEFAULT — fail-safe deny
# ============================================================================

default decision := {
	"decision":   "deny",
	"reason":     "no policy matched, default deny",
	"trace_id": 0
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
#  "input": {
#    "authorization_request" : {
#      "principal": {
#        "user_id": "alice@example.com",
#        "display_name": "Alice Developer",
#        "preferred_username": "alice@corp.com",
#        "acr": "mfa",
#        "groups": ["developers", "team-backend"],
#        "source_type": "oidc",
#        "raw_token": "eyJhbGc..."
#      },
#      "resource": {
#        "arguments": {
#          "path": "/workspace/src/main.go",
#          "content": "package main\n..."
#        },
#      },
#      "action": {
#        "service": "portcullis-localfs",
#        "tool_name": "write_file",
#      },
#      "context": {
#        "escalation_tokens": [
#          {
#            "token_id": "esc-12345",
#            "raw": "eyJhbGc...",
#            "granted_by": "bob.manager@example.com"
#          }
#        ]
#    },
#    "session_id": "session-abc123",
#    "trace_id": "req-xyz789"    
#  }
# 


principal := input.authorization_request.principal
action    := input.authorization_request.action
resource  := input.authorization_request.resource
context   := input.authorization_request.context

trace_id := object.get(input, "trace_id", 0)



escalation_grant_list := util.find_applicable_escalation_grants( context.escalation_tokens, action, principal, data.config.escalation_secret)


response_list contains { "decision":   "deny",	
			  "reason":  "invalid input request",
			  "trace_id": trace_id } if {

				not util.is_valid_request( input )

			  }


rules_section := object.get(data.portcullis.mcp, [action.service, action.tool_name], null)


response_list contains { "decision" : "deny", 
			  "reason" : "Denied by rule",
			  "trace_id": trace_id } if {


				not rules_section.deny == null
				allowdeny.request_matches_rule_criteria( input.authorization_request, rules_section.deny )

			  }


response_list contains { "decision" : "allow",
			  "reason" : "Allowed by rule",
			  "trace_id" : trace_id } if {

				not rules_section.allow == null
				print("#DEBUG: request: ", input.authorization_request)
				allowdeny.request_matches_rule_criteria( input.authorization_request, rules_section.allow )

			  }


response_list contains { "decision" : "allow",
			  "reason" : "Allowed by escalation token",
			  "trace_id" : trace_id } if {

				not rules_section.escalate == null

				count(escalation_grant_list) > 0

				# it must meet the base criteria for escalate.  For escalation, this can include both
				# positive rules (the request argument match the criteria for escalation)
				# and also negative rules (the principal must not be in one of the escalation groups)
				escalate.request_matches_base_criteria( input.authorization_request, rules_section.escalate)

				print("#DEBUG: allow scenario: we match the base case, do we match the escalation case?")
				print("#DEBUG++: escalation_grants: ", escalation_grant_list)

				# and it meets the criteria of at least one escalation token
				# this will also have two ways to match - with the escalated temporary group membership,
				# the user is in one of the 'escalate_to_groups' groups
				#
				# and/or the token includes argument-based permissions that verify that the caller is authorized 
				# to use said argument(s) in fulfillment of its objective
				#
				escalate.request_matches_escalation_criteria( 
						input.authorization_request, 
						rules_section.escalate, 
						escalation_grant_list )

				# the most exciting case!
				# print("#DEBUG: request meets the criteria of the escalation token")


			  }

response_list contains {
				"decision" : "escalate",
			  	"reason" : "Request is not approved, but can be escalated",
				"escalation_scope" : escalation_scope,
			  	"trace_id" : trace_id } if {

					not rules_section.escalate == null
					escalate.request_matches_base_criteria( input.authorization_request, rules_section.escalate )
					
#					print("#DEBUG: escalate scenario: we match the base case, do we match the escalation case?")
#					print("#DEBUG++: escalation_grants: ", escalation_grant_list)

					# why are we checking this? Because if the request does meet the escalation
					# criteria, it's approved, and no longer needs to be escalated
					#
					not escalate.request_matches_escalation_criteria( 
							input.authorization_request, 
							rules_section.escalate, 
							escalation_grant_list )

					# now we need to tell the system what kind of JWT claims would satisfy the
					# requirements of this request to allow for successful escalation
					#
					escalation_scope := escalate.find_matching_escalation_criteria( 
							input.authorization_request, 
							rules_section.escalate,
							escalation_grant_list)
				}


#
# if there are no table-based rules that apply in this scenario, check to see
# if there are any custom rules that generate a valid decision
#
decision := custom.decision if {
	count(response_list) == 0
}



decision := digest.evaluate_response_list( response_list, trace_id ) if {
	count(response_list) > 0
}



#
# changing this logic - if there is no policy rule, before giving up, we'll defer to the custom.decision
#
# response_list contains { "decision":   "deny",	
#			  "reason":  sprintf("no policy rules found for mcp: %s, tool: %s", [action.service, action.tool_name]),
#			  "trace_id": trace_id } if {
#
#				rules_section == null
#			  }








