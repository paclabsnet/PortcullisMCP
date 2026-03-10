package portcullis.util


import rego.v1












any_arg_restriction_rule_honored( arg_restriction_rule_array, request_args) := true if {

   some restriction in arg_restriction_rule_array
      arg_restriction_honored( restriction, request_args )
   
} else := no_arg_restrictions_to_honor( arg_restriction_rule_array )


no_arg_restrictions_to_honor( arg_restriction_rule_array ) := true if {
   count(arg_restriction_rule_array) == 0
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


