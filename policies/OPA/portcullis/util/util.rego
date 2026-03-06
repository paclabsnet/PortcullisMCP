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

request_matches_criteria( request, rules ) := true if {

   "groups" in object.keys(rules)
   not "arg_restrictions" in object.keys(rules)

   # if there are group rules, but no arg restrictions, we just have
   # to test the group match
   user_identity_has_matching_group( request.user_identity, rules.groups)


} else := request_matches_criteria_groups_and_arg_restrictions( request, rules )


request_matches_criteria_groups_and_arg_restrictions( request, rules ) := true if {

   "groups" in object.keys(rules)
   "arg_restrictions" in object.keys(rules)
   
   # we have to match both criteria around groups and arg restrictions
   user_identity_has_matching_group( request.user_identity, rules.groups)
   request_matches_arg_restrictions( request, rules.arg_restrictions)

# we can't get here unless we know that arg restrictions exist, so this should
# be safe
} else := request_matches_arg_restrictions( request, rules.arg_restrictions )



#
# 
#
request_matches_arg_restrictions( request, arg_restriction_array ) := true if {

   all_arg_restrictions_honored( arg_restriction_array, request.args)

} else := false



request_matches_criteria_with_escalation( request, rules, service, tool_name, jwt_secret) := true if {

   # simple case - the request matches the core crit
   request_matches_criteria(request, rules)
} else := request_matches_escalation_criteria( request, rules, service, tool_name, jwt_secret )



# we decode the valid escalation JWTs into an array, and then
# check the array elements against the rules
request_matches_escalation_criteria( request, rules, service, tool_name, jwt_secret ) := true if {


   escalation_data := [ claims | 
      some token in request.escalation_tokens
      [valid, _, claims ] := io.jwt.decode_verify(token.raw, {"secret": jwt_secret})
      valid == true
   ]

   allowed_groups := object.get(rules, "group", ["*"])

   escalation_matches_group_service_tool_and_request_args( 
            escalation_data, 
            allowed_groups, 
            service, 
            tool_name, 
            request.args )   

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
      user_identity, 
      request_args, 
      escalation_data,  
      allowed_groups, 
      service, 
      tool ) := true if {

   user_identity_has_matching_group( user_identity, allowed_groups)

} else := escalation_matches_group_service_tool_and_request_args( 
      escalation_data, 
      allowed_groups, 
      service, 
      tool, 
      request_args )


#
# simple case - is there an intersection between the user groups and the allowed groups
#
# special initial case - if the allowed_groups contains the simple string "*", that's
# a wildcard match
#
user_identity_has_matching_group( user_identity, allowed_groups ) := true if {
  
  "*" in allowed_groups

} else := arrays_share_element( user_identity.groups, allowed_groups)



#
#  We iterate over the escalation records. We're looking for one that matches the service and tool, and grants the
#  appropriate group membership. If the escalation record includes an arg restriction, we iterate over the elements
#  in the arg restriction and match appropriately 
#
escalation_matches_group_service_tool_and_request_args( 
      escalation_data, 
      allowed_groups, 
      service, 
      tool, 
      request_args) := true if {

  some record in escalation_data
     arrays_share_element( record.portcullis.groups, allowed_groups)
     service in record.portcullis.services
     tool in record.portcullis.tools
     all_arg_restrictions_honored( record.arg_restrictions, request_args)	

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

  key_path_array := split(restriction.key_path, ".")
   
  element := traverse_json( request_args, key_path_array)

  arg_restriction_honored_type_ladder( element, restriction )

} else := false



arg_restriction_honored_type_ladder( element, restriction ) := true if {
   
   restriction.type == "prefix"
   
   startswith(restriction.data, element)

} else := false   # if we need other types of restrictions, we can add them here fairly gracefully





element_does_not_exist_but_is_not_required( request_args, key_path_array, required ) := true if {
   not traverse_json( request_args, key_path_array)
   required == false 
}



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
traverse_json(obj, path) := value if {
    walk(obj, [path, value])
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
# Data fetching
#

# convenience method for traversing down a set of keys. This specifically
# works for a two-element array. Building a three-element version of this
# is straightforward, but I don't need it right now
traverse_json_2( json_object, key_array, default_value ) := result if {
   key_array[0] in object.keys(json_object)

   sub_object := object.get(json_object, key_array[0], default_value)

   key_array[1] in object.keys( sub_object)
   final_object := object.get(sub_object, key_array[1], default_value)

   result := final_object
} else := default_value


#######################################
# 
# input validation
#

is_valid_request( request )  := true if {

  "service" in object.keys(request)
  "tool_name" in object.keys(request)
  "user_identity" in object.keys(request)
  "groups" in object.keys(request.user_identity)
  "request_id" in object.keys(request)

} else := false