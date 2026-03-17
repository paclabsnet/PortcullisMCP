# EXAMPLE POLICY — Hand-written Rego rules
#
# This is one example of how an operator might write Portcullis policy.
# Rules are written explicitly in Rego rather than evaluated from a data table.
# Neither approach is required — use whatever best fits your organization.
#
# The PDP endpoint:
#   POST /v1/data/portcullis/custom/decision

package portcullis.custom

import rego.v1
import data.portcullis.util
import data.portcullis.allowdeny
import data.portcullis.escalate

#
# The input request will look something like:
# 
# {
#  "input": {
#    "principal": {
#      "user_id": "alice@example.com",
#      "display_name": "Alice Developer",
#      "groups": ["developers", "team-backend"],
#      "source_type": "oidc",
#      "raw_token": "eyJhbGc..."
#    },
#    "resource": {
#      "arguments": {
#        "path": "/workspace/src/main.go",
#        "content": "package main\n..."
#      },
#    },
#    "action": {
#      "service": "portcullis-localfs",
#      "tool_name": "write_file",
#    },
#    "context": {
#      "escalation_tokens": [
#        {
#          "token_id": "esc-12345",
#          "raw": "eyJhbGc...",
#          "granted_by": "bob.manager@example.com"
#        }
#      ],
#      "session_id": "session-abc123",
#      "request_id": "req-xyz789"
#    }
#  }
# }



# ============================================================================
# DEFAULT — fail-safe deny
# ============================================================================

default decision := {
	"decision":   "deny",
	"reason":     "policy processing error, default deny",
	"request_id": 0
}

principal := input.authorization_request.principal
action    := input.authorization_request.action
resource  := input.authorization_request.resource
context   := input.authorization_request.context

request_id := object.get(input, "request_id", 0)



#
# process the escalation tokens attached to the input
#  
#
escalation_grant_list := util.find_applicable_escalation_grants( context.escalation_tokens, action, data.config.escalation_secret)



#
#  general deny rules
#

response_list contains 
				{ "decision":"deny", 
				  "reason":"Denied - MCP is not in scope", 
				  "request_id": request_id} if {

   not input.service in ["portcullis-localfs", "mock-enterprise-api", "fetch"]

}


response_list contains 
				{ "decision":"deny", 
				  "reason":"Denied - localfs tool is not recognized", 
				  "request_id": request_id} if {

   action.service in ["portcullis-localfs"]
   not action.tool_name in ["read_file", "read_text_file", "read_media_file", "read_multiple_files", "write_file", 
   						"edit_file", "create_directory", "list_directory", "list_directory_with_sizes", 
						"directory_tree", "move_file", "search_files", "copy_file", "delete_file", 
						"search_within_files", "get_file_info", "list_allowed_directories"]

}


response_list contains 
				{ "decision":"deny", 
				  "reason":"Denied - mock-enterprise-api tool is not recognized", 
				  "request_id": request_id} if {

   action.service in ["mock-enterprise-api"]
   not action.tool_name in ["get_customer", "update_order_status", "query_inventory", "delete_order"]

}


#######################################
#
# tool-specific deny rules
#


response_list contains 
				{ "decision":"deny", 
				  "reason":"Denied - media file extension not allowed", 
				  "request_id": request_id} if {

   action.service in ["portcullis-localfs"]
   action.tool_name in ["read_media_file"]
   some extension in ["gz"]
      endswith(resource.arguments.path.filename.extension, extension)

}

response_list contains 
				{ "decision":"deny", 
				  "reason":"Denied - write destination not allowed", 
				  "request_id": request_id} if {

   action.service in ["portcullis-localfs"]
   action.tool_name in ["write_file"]
   some prefix in [ "C:\\Windows" ,
                    "C:\\ProgramData",
                    "/boot" ,
                    "/proc" ,
                    "/sys" ,
                     "/etc" ,
                     "/lib" ,
                     "~/.ssh" ,
                     "~/.gnupg"]
	   startswith( resource.arguments.path, prefix)

}


###########################################################################
#
# escalation scenarios.  This includes both the cases where we
# return 'escalate', indicating that the user needs to approve of
# the action, and the case where the escalation_tokens grant the
# AI the permission to do the new thing
#


response_list contains 
				{ "decision":"escalate", 
				  "reason":"This request requires escalated privilege", 
				  "request_id": request_id} if {

   action.service in ["portcullis-localfs"]
   action.tool_name in ["write_file"]
   some prefix in [ "C:\\Program Files", "C:\\Program Files (x86)" , "/var" ]
		startswith(resource.arguments.path, prefix)
	
	# so we've matched the escalation base case. If we have any tokens that
	# grant the agent permission, we would fail this case, and pass the
	# allow case below

    not escalate.escalation_grant_matches_service_tool_and_request_args(
			escalation_grant_list,
			action.service,
			action.tool_name,
			resource.arguments)


}



response_list contains 
				{ "decision":"allow", 
				  "reason":"This request is allowed because of escalated privilege", 
				  "request_id": request_id} if {

   action.service in ["portcullis-localfs"]
   action.tool_name in ["write_file"]
   some prefix in [ "C:\\Program Files", "C:\\Program Files (x86)" , "/var" ]
		startswith(resource.arguments.path, prefix)
	
	# so we've matched the escalation base case. If we have any tokens that
	# grant the agent permission, we would fail this case, and pass the
	# allow case below

    escalate.escalation_grant_matches_service_tool_and_request_args(
			escalation_grant_list,
			action.service,
			action.tool_name,
			resource.arguments)


}


#
#  mock-enterprise-api
#


response_list contains 
				{ "decision":"escalate", 
				  "reason":"This request requires escalated privilege", 
				  "request_id": request_id} if {

	action.service in ["mock-enterprise-api"]
	action.tool_name in ["get_customer"]
		
	not util.has_group_membership(principal.groups, ["admin", "developer", "clerk"])

	# so we've matched the escalation base case. If we have any tokens that
	# grant the agent permission, we would fail this case, and pass the
	# allow case below

    not escalate.escalation_grant_matches_service_tool_and_request_args(
			escalation_grant_list,
			action.service,
			action.tool_name,
			[])


}


response_list contains 
				{ "decision":"allow", 
				  "reason":"This request is allowed because of escalated privileges", 
				  "request_id": request_id} if {

	action.service in ["mock-enterprise-api"]
	action.tool_name in ["get_customer"]
		
	not util.has_group_membership(principal.groups, ["admin", "developer", "clerk"])

	# so we've matched the escalation base case. If we have any tokens that
	# grant the agent permission, we would fail this case, and pass the
	# allow case below

    escalate.escalation_grant_matches_service_tool_and_request_args(
			escalation_grant_list,
			action.service,
			action.tool_name,
			[])


}



###################################################################
#
#  explicit allow rules
#
response_list contains 
				{ "decision":"allow", 
				  "reason":"Allowed - in authorized group", 
				  "request_id": request_id} if {

   action.service in ["portcullis-localfs"]
   action.tool_name in ["delete_file"]
   util.has_group_membership( principal.groups, ["admin"])

}




response_list contains 
				{ "decision":"allow", 
				  "reason":"Allowed - in authorized group", 
				  "request_id": request_id} if {

	action.service in ["portcullis-localfs"]
    action.tool_name in ["read_file", "read_text_file", "read_media_file", "read_multiple_files", 
						 "write_file", "edit_file", "create_directory", "list_directory", 
						 "list_directory_with_sizes", "directory_tree", "move_file", "search_files",
						 "copy_file", "search_within_files", "get_file_info", "list_allowed_directories"]

    util.has_group_membership( principal.groups, ["*"]) 
}


#
#  allow rules for mock-enterprise-api
#


response_list contains 
				{ "decision":"allow", 
				  "reason":"Allowed - in authorized group", 
				  "request_id": request_id} if {

   action.service in ["mock-enterprise-api"]
   action.tool_name in ["update_order_status"]
   util.has_group_membership( principal.groups, ["admin"])

}

response_list contains 
				{ "decision":"allow", 
				  "reason":"Allowed - in authorized group", 
				  "request_id": request_id} if {

   action.service in ["mock-enterprise-api"]
   action.tool_name in ["delete_order"]
   util.has_group_membership( principal.groups, ["admin"])

}


response_list contains 
				{ "decision":"allow", 
				  "reason":"Allowed - in authorized group", 
				  "request_id": request_id} if {

   action.service in ["mock-enterprise-api"]
   action.tool_name in ["query_inventory"]
   util.has_group_membership( principal.groups, ["*"])

}



response_list contains 
				{ "decision":"allow", 
				  "reason":"Allowed - in authorized group", 
				  "request_id": request_id} if {

   action.service in ["mock-enterprise-api"]
   action.tool_name in ["get_customer"]
   util.has_group_membership( principal.groups, [ "admin", "developer", "clerk" ])

}


#########################################################################
#
# Fetch
#

response_list contains 
				{ "decision":"deny", 
				  "reason":"denied - competitive website job listing", 
				  "request_id": request_id} if {

   action.service in ["fetch"]
   action.tool_name in ["fetch"]
   startswith(resource.arguments.host, "competitor.com")
   startswith(resource.arguments.path, "/v1/jobs")

}


response_list contains 
				{ "decision":"escalate", 
				  "reason":"escalation required to visit competitor's product API", 
				  "escalation_scope" : escalation_scope,
				  "request_id": request_id} if {

   action.service in ["fetch"]
   action.tool_name in ["fetch"]
   startswith(resource.arguments.host, "competitor.com")
   startswith(resource.arguments.path, "/v1/products")

   not escalate.escalation_grant_matches_service_tool_and_request_args(
			escalation_grant_list,
			action.service,
			action.tool_name,
			resource.arguments)

	# now we need to tell the system what kind of JWT claims would satisfy the
	# requirements of this request to allow for successful escalation
	#
	escalation_scope := escalate.find_matching_escalation_criteria( 
			input.authorization_request, 
				{"arg_restrictions":[{ "type":"and", "list" :[
                    { "type":"prefix", "key_path": "host", "data": "competitor.com" },
                    { "type":"prefix", "key_path": "path", "data": "/v1/products" }
                ]}]},
			escalation_grant_list)	

}



response_list contains 
				{ "decision":"allow", 
				  "reason":"allowed to visit competitor's product page after escalation", 
				  "request_id": request_id} if {

   action.service in ["fetch"]
   action.tool_name in ["fetch"]
   startswith(resource.arguments.host, "competitor.com")
   startswith(resource.arguments.path, "/v1/products")

   escalate.escalation_grant_matches_service_tool_and_request_args(
			escalation_grant_list,
			action.service,
			action.tool_name,
			resource.arguments)

}






response_list contains 
				{ "decision":"escalate", 
				  "reason":"escalation required to visit styra/open policy agent, for the purposes of testing", 
				  "escalation_scope" : escalation_scope,
				  "request_id": request_id} if {

   action.service in ["fetch"]
   action.tool_name in ["fetch"]
   some x in ["styra.com", "openpolicyagent.com"]
     startswith(lower(resource.arguments.host), x)

   not escalate.escalation_grant_matches_service_tool_and_request_args(
			escalation_grant_list,
			action.service,
			action.tool_name,
			resource.arguments)


	# now we need to tell the system what kind of JWT claims would satisfy the
	# requirements of this request to allow for successful escalation
	#
	escalation_scope := escalate.find_matching_escalation_criteria( 
			input.authorization_request, 
			{ "arg_restrictions":[
				{ "type":"prefix","key_path":"host", "data":"styra.com"},
				{ "type":"prefix","key_path":"host", "data":"openpolicyagent.com"}
			]},
			escalation_grant_list)	


}











response_list contains 
				{ "decision":"allow", 
				  "reason":"allowed to visit competitor's product page after escalation", 
				  "request_id": request_id} if {

   action.service in ["fetch"]
   action.tool_name in ["fetch"]
   some x in ["styra.com", "openpolicyagent.com"]
     startswith(lower(resource.arguments.host), x)

   escalate.escalation_grant_matches_service_tool_and_request_args(
			escalation_grant_list,
			action.service,
			action.tool_name,
			resource.arguments)

}




response_list contains 
				{ "decision":"allow", 
				  "reason":"Allowed - in authorized group", 
				  "request_id": request_id} if {

   action.service in ["fetch"]
   action.tool_name in ["fetch"]
   util.has_group_membership( principal.groups, ["*"])

}








response_list contains 
				{ "decision":"escalate", 
				  "reason":"escalation required to visit styra/open policy agent, for the purposes of testing", 
				  "escalation_scope" : escalation_scope,
				  "request_id": request_id} if {

   action.service in ["fetch"]
   action.tool_name in ["fetch_url"]
   some x in ["styra.com", "openpolicyagent.org", "www.styra.com", "www.openpolicyagent.org"]
     startswith(lower(resource.arguments.host), x)

   not escalate.escalation_grant_matches_service_tool_and_request_args(
			escalation_grant_list,
			action.service,
			action.tool_name,
			resource.arguments)


	# now we need to tell the system what kind of JWT claims would satisfy the
	# requirements of this request to allow for successful escalation
	#
	escalation_scope := escalate.find_matching_escalation_criteria( 
			input.authorization_request, 
			{ "arg_restrictions":[
				{ "type":"prefix","key_path":"host", "data":"styra.com"},
				{ "type":"prefix","key_path":"host", "data":"openpolicyagent.org"},
				{ "type":"prefix","key_path":"host", "data":"www.styra.com"},
				{ "type":"prefix","key_path":"host", "data":"www.openpolicyagent.org"}
			]},
			escalation_grant_list)	


}



response_list contains 
				{ "decision":"allow", 
				  "reason":"allowed to visit competitor's product page after escalation", 
				  "request_id": request_id} if {

   action.service in ["fetch"]
   action.tool_name in ["fetch_url"]
   some x in ["styra.com", "openpolicyagent.org", "www.styra.com", "www.openpolicyagent.org"]
     startswith(lower(resource.arguments.host), x)

   escalate.escalation_grant_matches_service_tool_and_request_args(
			escalation_grant_list,
			action.service,
			action.tool_name,
			resource.arguments)

}






# non-business-hours request
# response_list contains { "decision" : "deny", 
#				"reason" : "no access during non-business hours: (Mon–Fri 08:00–18:00 UTC)", 
#				"request_id" : request_id } if {
#    now := time.now_ns()
#    day  := time.weekday(now)   # 0=Sunday, 6=Saturday
#    hour := time.clock(now)[0]
#	day in [0,6]
#    hour < 8
#	hour > 18
# }






#############################################################################
# Boilerplate
#
# the following stuff is the same for both custom and tabular rule 
# processing. I am reasonably fluent in Rego, but not enough to 
# turn this into common code
#







# no response, deny
decision := { "decision" : "deny", 
				"reason" : "no matching rule found", 
				"request_id" : request_id } if {
					count(response_list) == 0
}


#
# if the request doesn't have the necessary fields, it's
# invalid and should be denied
#
response_list contains { "decision":   "deny",	
			  "reason":  "invalid input request",
			  "request_id": request_id } if {

				not util.is_valid_request( input )

}



#
# we'll get 0 or more results from the policy logic. We can
# then make some high-level policy rules based on the 
# results.
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


#
# general rules:
# 1) If there are any denies, it's a deny
# 2) If there are any escalates, but no denies, it's escalate
# 3) if there are allows, and no deny/escalate results, it's allow
#
#  We could respond with all of the denies. For the moment, we'll
# just respond with the first one.
#
decision := deny_result if {
	count(deny_list) > 0
	deny_result := deny_list[0]
}


decision := escalate_result if {
	count(deny_list) == 0
	count(escalate_list) > 0
	escalate_result := escalate_list[0]
}


decision := allow_result if {
	count(deny_list) == 0
	count(escalate_list) == 0
	count(allow_list) > 0
	allow_result := allow_list[0]
}


