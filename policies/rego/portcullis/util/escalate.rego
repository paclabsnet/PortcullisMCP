package portcullis.escalate

import rego.v1


import data.portcullis.util


#
#  BASE CASE - No escalation tokens apply
#
request_matches_base_criteria( request, rules) := true if {

    request_principal_not_in_escalation_group( request, rules)

} else := request_not_in_escalation_group_and_maches_arg_restrictions( request, rules)


# the simplest case - there are no argument restriction rules, and there's just
# a list of groups to which the user doesn't belong normally
request_principal_not_in_escalation_group( request, rules) := true if {

   print("#DEBUG: request_principal_not_in_escalation_group: request: ", request, ", rules: ", rules)

   "escalate_to_groups" in object.keys(rules)
   not "arg_restrictions" in object.keys(rules)

   print("#DEBUG++: principal groups: ", request.principal.groups, ", escalate_to_groups: ", rules.escalate_to_groups)

   not util.has_group_membership( request.principal.groups, rules.escalate_to_groups)

} else := request_has_arg_restrictions( request, rules)


# there are both requirements that the user not belong to a particular group
# and that the request adhere to certain argument criteria
request_not_in_escalation_group_and_maches_arg_restrictions( request, rules) := true if {

   "escalate_to_groups" in object.keys(rules)
   "arg_restrictions" in object.keys(rules)
   
   # we have to match both criteria. the negative test for escalate_to_groups
   # and the positive test for arg restrictions
   not util.has_group_membership( request.principal.groups, rules.escalate_to_groups)
   util.any_arg_restriction_rule_honored( rules.arg_restrictions, request.resource.arguments)

} else := util.any_arg_restriction_rule_honored( rules.arg_restrictions, request.resource.arguments)


request_has_arg_restrictions( request, rules ) := true if {

    print("#DEBUG: request_has_arg_restrictions: ", rules)

   "arg_restrictions" in object.keys(rules)

   print("#DEBUG++: comparing arg_restrictions against arguments ", request.resource.arguments)

   util.any_arg_restriction_rule_honored( rules.arg_restrictions, request.resource.arguments)

}



################################
#
# ESCALATION CASE
#

# We check the escalation_grants to see if any of them are a match for the request
#
# This is probably the most subtle element in the whole system, so let's spend a little time
# explaining what's going on
#
# Let's say that the agent wants to use the "filesystem" MCP, and the tool: write_file to write
# records to the file /var/log/whatever.log
#
# And the default policy for write_file to /var is escalate. 
#
# The user is notified that the AI wants to escalate this request.
# (Let's assume that it's a reasonable request)
#
# The user creates a JWT that grants the following:
# service: filesystem
# tool_name: write_file
# arg_restriction (shorthand):  /var/log/whatever.log
#
# The next time the AI asks to do this, this JWT is included
#
# when it gets to this point, we've already validated the JWT, so now we just need to
# see that the parameters of the request (/var/log/whatever.log) match the arg_restrictions
# in the JWT.  
#
# They do match.  So this request can now be considered allowed.  
#
# The key insight: the presence of a signed JWT that matches the parameters of the request is
# sufficient to allow the request to proceed.  "But they're both in the same request, how is 
# that secure?" I hear you ask. 
#
# The answer is in two parts:
# a) the AI has no ability to sign or add JWTs to the request - all of that happens
#    in a way that is opaque to the AI. All the AI agent can do is create MCP requests
# b) the creation of the JWT can be governed by security processes that are outside the
#    scope of Portcullis, and the security of JWTs is well-established
#
# In principle, an organization that is not careful about creating the escalation tokens
# *could* allow a user to exploit this to give them the ability to coerce the AI agent into
# doing things that the user can't do themselves (subject to any seecurity in the MCP, etc)
#
# Having said that, if the user deliberately gives the agent a token that allows the agent to
# delete a database, the signed token demonstrates that the user is accountable for this
# outcome.
#
request_matches_escalation_criteria( request, rules, escalation_grant_list) := true if {

   escalation_groups := object.get(rules, "escalate_to_groups", ["*"])   

   print("#DEBUG: request_matches_escalation_criteria: grants: ", escalation_grant_list)

   request_arguments := object.get(request, ["resource", "arguments"], [])

   escalation_grant_matches_group_service_tool_and_request_args( 
            escalation_grant_list, 
            escalation_groups, 
            request.action.service, 
            request.action.tool_name, 
            request_arguments )   

} else := false



#
# we need to look at the request and compare the arguments in the request to the arg_restrictions in the escalate
# rules to find the ones that match.
#
# for each one that matches (typically only one) we'll create a hybrid arg_restriction, which includes the
# restriction type (suffix, prefix, etc) from the arg_restriction with the data from the argument itself 
#
# Example:  The AI wishes to write to /var/log/whatever.log, and the arg_restriction is for prefix "/var"
#           we would create an escalation_claim for an arg_restriction: 
#                   { "type":"prefix", 
#                     "key_path":<from arg_restriction">
#                     "data":"/var/log/whatever.log" 
#                   }
#
#          this is the minimal grant required - it gives the AI exactly the specific access it seeks and
#          nothing more broad
#
# @TODO: include advisory claims about group membership, but they won't be enforceable through the Guard
# process, which will only allow the user to approve argument escalation approvals
#
#
find_matching_escalation_criteria( request, rules, escalation_grant_list) := escalation_claim_list if {

   # if there aren't any arg restrictions, we can't match them
   "arg_restrictions" in object.keys(rules)
   count(rules.arg_restrictions) > 0

   request_arguments := object.get(request, ["resource", "arguments"], [])

   escalation_claim_list := find_rule_arg_restrictions_matching_request_args(
      rules.arg_restrictions,
      request_arguments
   )

} else := []




#
#  This function is used in the scenario where we know we're in the escalation case (in other words
#  the caller's request satisfies the requirements for the arg_restrictions associated with 
#  escalation), and we need to create the escalation_claims that can be used to create a token
#  that would allow the user to grant the AI the necessary escalated privilege
#
#  we iterate through the existing restrictions, and any that 'hit' are converted into 
#  escalation_claim records. The assumption is that those escalation_claim records will
#  be used by another system (for example: Portcullis-Guard) to create the escalation_token
#  
#
find_rule_arg_restrictions_matching_request_args(
    rule_arg_restrictions,
    request_arguments) := escalation_claim_list if {
   
    rule_element_matched_list := util.arg_restriction_matched_list( rule_arg_restrictions, request_arguments)
    
    # count the matches
    count(rule_element_matched_list) > 0

    # each hybrid record includes the type and key_path from the rule, and the 
    # data from the appropriate request_argument

    escalation_claim_list := [ hybrid | 
                                 some record in rule_element_matched_list
                                    hybrid := { "type": record.rule.type, 
                                                "key_path" : record.rule.key_path,
                                                "data" :  record.arg }
                             ]
    
    print("#DEBUG: find_rule_arg_restrictions_matching_request_args: ", escalation_claim_list)


} else := [] 




#
#  We iterate over the escalation records. We're looking for one that matches the service and tool, and grants the
#  appropriate group membership. If the escalation record includes an arg restriction, we iterate over the elements
#  in the arg restriction and match appropriately 
#
escalation_grant_matches_group_service_tool_and_request_args( 
      escalation_grant_list, 
      escalation_groups, 
      service, 
      tool, 
      request_args) := true if {


  print("#DEBUG: escalation_matches_group_service_tool_and_request_args: escalation_groups:",escalation_groups,", service: ",service,", tool:",tool,", request: ", request_args) 
  print("#DEBUG++: escalation grant list: ", escalation_grant_list)

  some escalation_grant in escalation_grant_list

     print("#DEBUG++: escalation grant: ", escalation_grant)

     # note that the first parameter here is the groups from the 
     util.has_group_membership( escalation_grant.portcullis.groups, escalation_groups)

     print("#DEBUG++: has group memebership: true")

     # @TODO: these two tests are probably redundant, TBD 
     service in escalation_grant.portcullis.services
     tool in escalation_grant.portcullis.tools

     print("#DEBUG++: arg restrictions: ", escalation_grant.portcullis.arg_restrictions," request_args: ", request_args)
     util.any_arg_restriction_rule_honored( escalation_grant.portcullis.arg_restrictions, request_args)	

     print("#DEBUG++: any_arg_restriction_honored: TRUE")

} else := false








