package portcullis.custom

import rego.v1
import data.portcullis.util
import data.portcullis.allowdeny
import data.portcullis.escalate
import data.portcullis.digest


# ============================================================================
# DEFAULT — fail-safe deny
# ============================================================================
# default decision := {
#    "decision" : "deny",
#    "reason" : "Policy logic failure during evaluation",
#    "trace_id" : trace_id
# }

principal := input.authorization_request.principal
action    := input.authorization_request.action
resource  := input.authorization_request.resource
context   := input.authorization_request.context

trace_id := object.get(input, "trace_id", 0)


#
# find all the policy scenarios that apply
#

#
# Creating a special response for the 'delete_customer' tool 
# which is not defined in the tabular decisions (there is not delete_customer tool)
#
#
response_list contains { "decision":   "workflow",	
			  "reason":  "this requires user group membership",
			  "trace_id": trace_id } if {

	action.service in ["mock-enterprise-api"]
	action.tool_name in ["delete_customer"]
		
	not util.has_group_membership(principal.groups, ["admin"])

}



response_list contains { "decision":   "allow",	
			  "reason":  "admin user",
			  "trace_id": trace_id } if {

	action.service in ["mock-enterprise-api"]
	action.tool_name in ["delete_customer"]
		
	util.has_group_membership(principal.groups, ["admin"])

}

decision := digest.evaluate_response_list( response_list, trace_id )







