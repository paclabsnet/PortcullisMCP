package portcullis.util


import rego.v1




#
# the rules have various criteria. 
# right now, there are two parts, both optional (although you would want one in most cases)
# - the allowed groups
# - the arg_restrictions
#
# we need to evaluate the input request against the criteria, in a way that is 
# mindful of the fact that some of the criteria are optional.

#
# starting scenario - there is a group requirement, but no argument
#                     restrictions
# we just have to match the allowed groups to any of the user's groups
#
request_matches_criteria( request, rules ) := true if {

   "groups" in object.keys(rules)
   not "arg_restrictions" in object.keys(rules)

   has_group_membership( request.principal.groups, rules.groups)

} else := request_matches_criteria_groups_and_arg_restrictions( request, rules )


# Second case - there are both group membership requirements and
#               argument restrictions
request_matches_criteria_groups_and_arg_restrictions( request, rules ) := true if {

   "groups" in object.keys(rules)
   "arg_restrictions" in object.keys(rules)
   
   # we have to match both criteria around groups and arg restrictions
   has_group_membership( request.principal.groups, rules.groups)
   request_matches_arg_restrictions( request, rules.arg_restrictions)

# we can't get here unless we know that arg restrictions exist, so this should
# be safe
} else := request_matches_arg_restrictions( request, rules.arg_restrictions )



#
# Third case - there aren't any group requirements, but there can be 
#              argument restrictions 
# Note that if there aren't any group requirements *or* argument restrictions, we will 
# fail. That's a design choice
#
request_matches_arg_restrictions( request, arg_restriction_array ) := true if {

   # print("DEBUG: request_matches_arg_restrictions: ", arg_restriction_array, " resource:", resource.resource.arguments)

   any_arg_restrictions_honored( arg_restriction_array, request.resource.arguments)

} else := false



request_matches_criteria_with_escalation( request, rules, escalation_grant_list) := true if {

   # simple case - the request matches the core crit
   request_matches_criteria(request, rules)
} else := request_matches_escalation_criteria( request, rules, escalation_grant_list )



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
request_matches_escalation_criteria( request, rules, escalation_grant_list ) := true if {

   allowed_groups := object.get(rules, "group", ["*"])

   escalation_matches_group_service_tool_and_request_args( 
            escalation_grant_list, 
            allowed_groups, 
            request.action.service, 
            request.action.tool_name, 
            request.resource.arguments )   

# we've already tested the core criteria, so if we get here, there's no
# way to succeed
} else := false


#
#          check the escalation token data against a variety of factors, to make sure there's a match
#          An escalation token grants use of certain tools and services, possibly in a
#          constrained way (for example, only certain paths), and grants membership in a particular
#          group or groups.  So we look through the escalation data to see if any of the records
#          are granting access to the specified tool and service that the user agent is seeking to use,
#          and then optionally if there are any arg_restrictions in the escalation data
#          (for example, that the escalation token only grants access to a particular directory), 
#          we validate that this request honors those requirements as well
#          
#   
#
has_matching_group_for_service_tool_and_request_args_with_escalation( 
      principal, 
      request_args, 
      escalation_grant_list,  
      allowed_groups, 
      service, 
      tool ) := true if {

   has_group_membership( principal.groups, allowed_groups)

} else := escalation_matches_group_service_tool_and_request_args( 
      escalation_grant_list, 
      allowed_groups, 
      service, 
      tool, 
      request_args )





#
#  We iterate over the escalation records. We're looking for one that matches the service and tool, and grants the
#  appropriate group membership. If the escalation record includes an arg restriction, we iterate over the elements
#  in the arg restriction and match appropriately 
#
escalation_matches_group_service_tool_and_request_args( 
      escalation_grant_list, 
      allowed_groups, 
      service, 
      tool, 
      request_args) := true if {


#  print("#DEBUG: escalation_matches_group_service_tool_and_request_args: allowed_groups:",allowed_groups,", service: ",service,", tool:",tool,", request: ", request_args) 
#  print("#DEBUG++: escalation grant list: ", escalation_grant_list)

  some record in escalation_grant_list

#     print("#DEBUG++: escalation record: ", record)

     has_group_membership( record.portcullis.groups, allowed_groups)

#     print("#DEBUG++: has group memebership: true")

     # @TODO: these two tests are probably redundant, TBD 
     service in record.portcullis.services

#     print("#DEBUG++: service match: true")

     tool in record.portcullis.tools

#     print("#DEBUG++: tool  match: true")


#     print("#DEBUG++: arg restrictions: ", record.portcullis.arg_restrictions," request_args: ", request_args)
     any_arg_restrictions_honored( record.portcullis.arg_restrictions, request_args)	

#     print("#DEBUG++: any_arg_restriction_honored: TRUE")

} else := false



#
#  arg restrictions help limit the scope of what the AI agent is allowed to do. 
#  there are various forms that a restriction might take, but for now we'll focus
#  on prefix restrictions
#
#  basically, we'll look at the array of arg restrictions and verify that each one
#  is honored in the request.
#
#  if required == true, the specified argument key *must* be in the request_args.
#  
#
all_arg_restrictions_honored( restriction_array, request_args) := true if {

   every restriction in restriction_array {
      arg_restriction_honored( restriction, request_args )
   }

} else := false


any_arg_restrictions_honored( restriction_array, request_args) := true if {

   some restriction in restriction_array
      arg_restriction_honored( restriction, request_args )
   
} else := false



#
# check one specific arg_restriction
#
arg_restriction_honored( restriction, request_args) := true if {

  key_path_array := split(restriction.key_path, ".")

  # this only returns true if the element doesn't exist and is not required
  # 
  element_does_not_exist_but_is_not_required( request_args, key_path_array, object.get(restriction, "required", true))

  # if we get here, it means the element didn't exist, but it wasn't required, so we've honored this restriction 

} else := arg_restriction_honored_existence_required( request_args,  restriction )


#
# most common case - the element is required, so first we verify that the element exists,
# and if it does, we verify that the element matches the restriction
#
arg_restriction_honored_existence_required( request_args, restriction) := true if {

#  print("#DEBUG: arg_restriction_honored_existence_required: request_args: ", request_args, ", restriction: ", restriction)

  key_path_array := split(restriction.key_path, ".")
   
  element := traverse_json( request_args, key_path_array)

  arg_restriction_honored_type_ladder( element, restriction )

} else := false



#
# right now, we just have prefix, but if we add other types of tests, we can
# add one a new function as the else clause for this restriction.type, and then add
# an else clause to that function for the next one, etc.
#
arg_restriction_honored_type_ladder( element, restriction ) := true if {
   
   # print("#DEBUG: arg_restriction_honored_type_ladder: element: ", element, " restriction: ", restriction)

   restriction.type == "prefix"
   
   startswith(element, restriction.data)

#   print("#DEBUG: TRUE: arg_restriction_honored_type_ladder: element: ", element, " restriction: ", restriction)


} else := false   # if we need other types of restrictions, we can add them here fairly gracefully





element_does_not_exist_but_is_not_required( request_args, key_path_array, required ) := true if {
   not object.get(request_args, key_path_array, null) == null
   required == false 
}

##############################################
#
# group membership evaluation, with wildcard support
#
has_group_membership( user_groups, allowed_groups) := true if {
   "*" in allowed_groups
} else := arrays_share_element( user_groups, allowed_groups)


##############################################
#
# JWT processing
#
#
# look through the escalation tokens and find all the ones that are:
# a) valid
# b) for the correct service and tool
#
# and return those
#
find_applicable_escalation_grants( escalation_tokens, action, jwt_secret ) := escalation_grant_list if {

   escalation_grant_list := [ claims | 
      some token in escalation_tokens
         [valid, _, claims ] := io.jwt.decode_verify(token.raw, {"secret": jwt_secret})
            valid == true
            action.service in claims.portcullis.services
            action.tool_name in claims.portcullis.tools
            # need to check for expiration for the token
      ]

} else := []





##############################################
#  
#  Deep utility functions
#
#

# this will traverse the json (duh) and return the value
# at the end of the walk.
#
# this is fairly expensive, but it's straightforward for 
# now, and sufficient for the purposes of proving the 
# concept(s)
#
traverse_json(obj, key_path_array) := value if {

#    print("#DEBUG: traverse_json: object: ",obj,", key_path_array: ", key_path_array)

    value := object.get(obj, key_path_array, null)

#    print("#DEBUG: traverse_json: value: ", value)

}




#
# simple intersection check. This doesn't care what types of items
# are in the arrays, but generally they will be strings
#
arrays_share_element(a, b) if {
    some x in a
      x in b
} else := false



#######################################
# 
# input validation
#

is_valid_request( document )  := true if {

  "authorization_request" in object.keys(document)

  auth_request := document.authorization_request

  "principal" in object.keys(auth_request)
    "groups" in object.keys(auth_request.principal)


  "action" in object.keys(auth_request)
   "service" in object.keys(auth_request.action)
   "tool_name" in object.keys(auth_request.action)

#  "request_id" in object.keys(request)

} else := false


