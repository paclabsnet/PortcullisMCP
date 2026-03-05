package portcullis.util


import rego.v1


#
# two stage check
#
# step 1 - if the user agent is a member of any of the groups that are authorized.  If this hits, we don't 
#          do any further checking of the escalation tokens
#
# step 2 - check the escalation token data against a variety of factors, to make sure there's a match
#          An escalation token grants use of certain tools and services, possibly in a
#          constrained way (for example, only certain paths), and grants membership in a particular
#          group or groups.  So we look through the escalation data to see if any of the records
#          are granting access to the specified tool and service that the user agent is seeking to use
#   
#
has_matching_group_for_service_tool_and_request_args( user_identity, request_args, escalation_data,  allowed_groups, service, tool ) := true if {

   user_identity_has_matching_group( user_identity, allowed_groups)

} else := escalation_matches_group_service_tool_and_request_args( escalation_data, allowed_groups, service, tool, request_args )


#
# simple case - is there an intersection between the user groups and the allowed groups
#
user_identity_has_matching_group( user_identity, allowed_groups ) := true if {
  
  arrays_share_element( user_identity.groups, allowed_groups)

} else := false


#
#  We iterate over the escalation records. We're looking for one that matches the service and tool, and grants the
#  appropriate group membership. If the escalation record includes an arg restriction, we iterate over the elements
#  in the arg restriction and match appropriately 
#
escalation_matches_group_service_tool_and_request_args( escalation_data, allowed_groups, service, tool, request_args) := true if {

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

  element_does_not_exist_but_is_not_required( request_args, key_path_array, restriction.required)


} else := arg_restriction_honored_existence_required( request_args,  restriction )




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
# simple intersection check
#
arrays_share_element(a, b) if {
    some x in a
      x in b
} else := false
