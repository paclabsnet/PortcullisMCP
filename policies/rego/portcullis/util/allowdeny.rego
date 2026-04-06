package portcullis.allowdeny


import rego.v1

import data.portcullis.util

#
# There are a bunch of ways that a request matches criteria, and there are two different
# paths - the 'base' path, and the path that includes escalation grant tokens.
#
#
# This is very tricky to get right, especially with the challenges of handling "or" in 
# rego.  
#
# AFter working through this logic several times trying to get it right, here's my current
# strategy (20260310)
#
# allow and deny evaluations have a relatively simple approach - look at the details of the
# request, and compare them to the rules.  If the request satisfies the rules' criteria,
# they pass
#
# escalation evaluations have a different behavior.  The escalate
# response is a little counterintuitive.  You want to return the 'escalate' response to 
# the caller when the request meets the criteria of the base case, but does *not* meet
# the criteria when you include the escalation token.  
#   - because when you meet the criteria when you include the escalation token, that should
#     represent an 'allow' response.
#
# we don't have to solve this problem here - the calling logic knows what types of rules it is
# evaluating, and can respond to the caller appropriately.  All we have to do is evaluate the
# request against the criteria and return true or false.
#
# but in practice, the escalate evaluation logic is different enough from the standard evaluation
# logic that it seems to make sense to separate them.  This will cause some repetitive
# logic, but that's preferable to confusing logic.
#

request_matches_rule_criteria( request, rules ) := true if {
   request_principal_in_rule_group( request, rules) 
} else := request_matches_principal_groups_and_arg_restrictions( request, rules)


# first test - does the principal belong to the appropriate group
request_principal_in_rule_group( request, rules) := true if {

   "groups" in object.keys(rules)
   not "arg_restrictions" in object.keys(rules)

   util.has_group_membership( request.principal.groups, rules.groups)

}


request_matches_principal_groups_and_arg_restrictions( request, rules ) := true if {

   "groups" in object.keys(rules)
   "arg_restrictions" in object.keys(rules)
   
   # we have to match both criteria around groups and arg restrictions
   util.has_group_membership( request.principal.groups, rules.groups)
   util.any_arg_restriction_rule_honored( rules.arg_restrictions, request )

# we don't have groups, but we do have arg restrictions
} else := util.any_arg_restriction_rule_honored( rules.arg_restrictions, request )


