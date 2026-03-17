package portcullis.util


import rego.v1







arg_restriction_matched_list( arg_restriction_rule_array, request_args) := rule_element_matched_list if {

   # because some of the matches can be an 'and' of multiple rules, we potentially get a mix of arrays
   # with one element, and arrays with multiple, and we want to flatten those out. The grants don't
   # need the 'and' criteria, 'and' is built-in to the logic of evaluating claims from the tokens
   # 
   unflattened_rule_element_matched_list := [ rule_element_matched_list |
                               some restriction in arg_restriction_rule_array
                                  rule_element_matched_list := arg_restriction_matched_type_ladder( restriction, request_args)
                           ]

   rule_element_matched_list := array.flatten(unflattened_rule_element_matched_list)
   
}


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

#  print("#DEBUG: arg_restriction_honored")

  key_path_array := split(restriction.key_path, ".")

  # this only returns true if the element doesn't exist and is not required
  # 
  element_does_not_exist_but_is_not_required( request_args, key_path_array, object.get(restriction, "required", true))

  # if we get here, it means the element didn't exist, but it wasn't required, so we've honored this restriction 

} else := arg_restriction_honored_existence_required( restriction, request_args )


#
# most common case - the element is required, so first we verify that the element exists,
# and if it does, we verify that the element matches the restriction
#
arg_restriction_honored_existence_required( restriction, request_args) := true if {

#  print("#DEBUG: arg_restriction_honored_existence_required: request_args: ", request_args, ", restriction: ", restriction)

  rule_element_matched_list := arg_restriction_matched_type_ladder( restriction, request_args )
  count(rule_element_matched_list) > 0

} else := false





#
# we can add as many different types as we want by creating this ladder
# of fail-through checks
#
arg_restriction_matched_type_ladder( restriction, request_args ) := rule_element_matched_list if {

   print("#DEBUG: arg_restriction_matched_type_ladder: ", request_args, ", ", restriction)

   lower(restriction.type) == "and"

   rule_element_matched_list := all_arg_restriction_rule_matched( restriction.list, request_args)

   print("#DEBUG++: rule_element_matched_list: ", rule_element_matched_list)

# prefix MUST be the next item on the ladder, or the all_arg_restriction function above won't work properly
} else := arg_restriction_matched_type_ladder_dereference_element( restriction, request_args)


#
# up until this point, we haven't been looking at the contents of the restriction, just
# the type. now we have to get into the details
#
arg_restriction_matched_type_ladder_dereference_element( restriction, request_args ) := rule_element_matched_list if {

  print("#DEBUG: arg_restriction_matched_type_ladder_deference_element: args:", request_args, ", restriction:", restriction)

  key_path_array := split(restriction.key_path, ".")
   
  element := traverse_json( request_args, key_path_array)

  rule_element_matched_list := arg_restriction_matched_type_ladder_prefix(restriction, element)

} else := []


#
# does the first part of the element match the restriction prefix
#
arg_restriction_matched_type_ladder_prefix( restriction, element ) := rule_element_matched_list if {
   
  print("#DEBUG: arg_restriction_matched_type_ladder_prefix: element:", element, ", ", restriction)

   lower(restriction.type) == "prefix"
   
   startswith(lower(element), lower(restriction.data))

   rule_element_matched_list := [ { "rule": restriction, "arg": element } ]

} else := arg_restriction_matched_type_ladder_suffix( restriction, element )


#
# does the end of the element match the restriction suffix
#
arg_restriction_matched_type_ladder_suffix( restriction, element ) := rule_element_matched_list if {

  print("#DEBUG: arg_restriction_matched_type_ladder_suffix: element:", element, ", ", restriction)

   lower(restriction.type) == "suffix"
   
   endswith(lower(element), lower(restriction.data))

   rule_element_matched_list := [ { "rule": restriction, "arg": element } ]

} else := arg_restriction_matched_type_ladder_whole( restriction, element )


#
# does the end of the element match the restriction suffix
#
arg_restriction_matched_type_ladder_whole( restriction, element ) := rule_element_matched_list if {

  print("#DEBUG: arg_restriction_matched_type_ladder_whole: element:", element, ", ", restriction)

   lower(restriction.type) == "whole"
   
   lower(element) == lower(restriction.data)

   rule_element_matched_list := [ { "rule": restriction, "arg": element } ]

} else := arg_restriction_matched_type_ladder_contains( restriction, element)




arg_restriction_matched_type_ladder_contains( restriction, element ) := rule_element_matched_list if {

  print("#DEBUG: arg_restriction_matched_type_ladder_contains: element:", element, ", ", restriction)

   lower(restriction.type) == "contains"
   
   contains(lower(element), lower(restriction.data))

   rule_element_matched_list := [ { "rule": restriction, "arg": element } ]

} else := []

#
# this is a bit of a 'pro gamer move'.  Rego does not support recursion. so we can't
# have this in a scenario where all_arg_restrictions calls any_arg_restrictions .  But in
# practice, that's probably fine. 
#
# the other hack that makes this a pro-gamer move is taking advantage of knowing that
# the prefix check is immediately after the 'AND' check on the ladder.  This requires
# discipline, which I do not love, because people forget.  But for the purposes of this
# proof of concept, it's fine.  
#
# Note also that the AND is implicitly required.  what would be the point of an AND if
# one of the restrictions were optional?
#
all_arg_restriction_rule_matched( arg_restriction_rule_array, request_args ) := rule_element_matched_list if {


#   print("#DEBUG: all_arg - array: ", arg_restriction_rule_array, ", request: ", request_args)

  #
  # we have <N> arg restrictions to look at, and so we'll go through each of them to see if one
  # of the arguments matches the arg restriction.     matched_arg_list always returns a single
  # element when you get to the dereference step on the ladder, so we know the match is the
  # first element.
  #
  # I know this is a little ugly, but I'm working with what I know
  # 
  rule_element_matched_list := [ rule_element_item | 
                                 some restriction in arg_restriction_rule_array
                                    child_rule_element_matched_list := arg_restriction_matched_type_ladder_dereference_element( restriction, request_args)
                                    count(child_rule_element_matched_list) > 0
                                    rule_element_item := child_rule_element_matched_list[0]
                                    
                      ]

   count(rule_element_matched_list) == count(arg_restriction_rule_array)

#   every restriction in arg_restriction_rule_array {
#
#       matched_arg_list := arg_restriction_matched_type_ladder_dereference_element( restriction, request_args)
#       count(match_list) > 0
#
#   }

} else := []





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

   print("#DEBUG: find_applicable_escalation_grants: ", action)
   print("#DEBUG++: escalation_tokens: ", escalation_tokens)

   escalation_grant_list := [ claims |
      some token in escalation_tokens
         [valid, _, claims ] := io.jwt.decode_verify(token.raw, {"secret": jwt_secret, "time": time.now_ns()})
            # print("#DEBUG++: valid, ", valid, ", claims: ",claims)
            valid == true
            action.service in claims.portcullis.services
            action.tool_name in claims.portcullis.tools
      ]

   # print("#DEBUG++: found grants: ", escalation_grant_list)   

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


