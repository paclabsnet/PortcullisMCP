package portcullis.util


import rego.v1


import data.portcullis.rule_match


#
# The argument matching stuff is a little more complicated than I would like. I'm not sure that
# I can make it less complicated without using various Rego shortcuts that make things hard to follow.
#
# 1) the AND scenario - we have an arg_restriction that is actually multiple arg_restrictions ANDed together
# 2) the regular scenario - we have a single arg_restriction
#
# In both of these scenarios, we have to extract the appropriate values from the request_args, 
# using the instructions in the arg_restriction as a guide to the extraction process
#
# Once we've gotten the correct data element out of the request_args, we can finally do the actual tests
# where we compare that element to the data in the arg_restriction, using the rule type implemented in the rule_match
# package.
#
#



#
# returns the array of 
#
find_arg_restriction_matches( arg_restriction_rule_array, request_body) := rule_element_matched_list if {

   # because some of the matches can be an 'and' of multiple rules, we potentially get a mix of arrays
   # with one element, and arrays with multiple, and we want to flatten those out. The grants don't
   # need the 'and' criteria, 'and' is built-in to the logic of evaluating claims from the tokens
   # 
   unflattened_rule_element_matched_list := [ rule_element_matched_list |
                               some restriction in arg_restriction_rule_array
                                  rule_element_matched_list := find_arg_restriction_matches_for_ANDED_group( restriction, request_body)
                           ]

   rule_element_matched_list := array.flatten(unflattened_rule_element_matched_list)
   
}


#
# returns true if any of the arg restriction requirements are met
#
any_arg_restriction_rule_honored( arg_restriction_rule_array, request_body) := true if {

   some restriction in arg_restriction_rule_array
      arg_restriction_honored( restriction, request_body )
   
} else := no_arg_restrictions_to_honor( arg_restriction_rule_array )


#
# returns true if there are no arg restrictions to evaluate
#
no_arg_restrictions_to_honor( arg_restriction_rule_array ) := true if {
   count(arg_restriction_rule_array) == 0
} else := false



#
# check one specific arg_restriction, which can be several sub-restrictions ANDED together
#
arg_restriction_honored( restriction, request_body) := true if {

  rule_element_matched_list := find_arg_restriction_matches_for_ANDED_group( restriction, request_body )
  count(rule_element_matched_list) > 0

} else := false   





#
# we can add as many different types as we want by creating this ladder
# of fail-through checks
#
find_arg_restriction_matches_for_ANDED_group( restriction, request_body ) := rule_element_matched_list if {

   # print("#DEBUG: find_arg_restriction_matches_for_ANDED_group: ", request_body, ", ", restriction)

   lower(restriction.type) == "and"

   rule_element_matched_list := find_every_arg_restriction_rule_matches( restriction.list, request_body)

   # print("#DEBUG++: rule_element_matched_list: ", rule_element_matched_list)

} else := find_arg_restriction_matches_for_single_element( restriction, request_body)


#
# up until this point, we haven't been looking at the contents of the restriction, just
# the type. now we have to get into the details and start comparing values to actual
# data restrictions
#
find_arg_restriction_matches_for_single_element( restriction, request_body ) := rule_element_matched_list if {

  # print("#DEBUG: find_arg_restriction_matches_for_single_element: args:", request_body, ", restriction:", restriction)

  # turn the dot notation path into an array of keys  "domain.host" -> ["domain","host"]
  key_path_array := split(restriction.key_path, ".")

  # 
  #  given a complex object, and an array of keys, traverse the elements of the object
  #  by following each key
  #   
  element := traverse_json( request_body, key_path_array)

  rule_element_matched_list := rule_match.match(restriction, element)

} else := []






#
#  if there are <N> arg restrictions, we test each one and build a list of matches.
#  if the match list is also size <N>, we know we have matched every restriction
#
find_every_arg_restriction_rule_matches( arg_restriction_rule_array, request_body ) := rule_element_matched_list if {

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
                                    child_rule_element_matched_list := find_arg_restriction_matches_for_single_element( restriction, request_body)
                                    count(child_rule_element_matched_list) > 0
                                    rule_element_item := child_rule_element_matched_list[0]
                                    
                      ]

  count(rule_element_matched_list) == count(arg_restriction_rule_array)

} else := []






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
find_applicable_escalation_grants( escalation_tokens, action, user, jwt_secret ) := escalation_grant_list if {

#   print("#DEBUG: find_applicable_escalation_grants: ", action)
#   print("#DEBUG++: escalation_tokens: ", escalation_tokens)

   escalation_grant_list := [ claims |
      some token in escalation_tokens
         [valid, _, claims ] := io.jwt.decode_verify(token.raw, {"secret": jwt_secret, "time": time.now_ns()})
            # print("#DEBUG++: valid, ", valid, ", claims: ",claims)
            valid == true
            action.service in claims.portcullis.services
            action.tool_name in claims.portcullis.tools
            user.user_id == claims.sub
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


