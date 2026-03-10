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

} else := false


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

     print("#DEBUG++: service match: true")

     tool in escalation_grant.portcullis.tools

     print("#DEBUG++: tool  match: true")

     print("#DEBUG++: arg restrictions: ", escalation_grant.portcullis.arg_restrictions," request_args: ", request_args)
     util.any_arg_restriction_rule_honored( escalation_grant.portcullis.arg_restrictions, request_args)	

     print("#DEBUG++: any_arg_restriction_honored: TRUE")

} else := false








