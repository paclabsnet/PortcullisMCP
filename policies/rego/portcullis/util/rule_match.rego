package portcullis.rule_match


import rego.v1


#
# the way Rego works, when you have multiple functions with the
# same name, Rego will try all of them to see which ones give
# back useful values (instead of returning undefined).
#
# The other way is a nested set of else clauses, and having written
# that before, it is one of the ugliest things I've ever had to
# write. This is much better
#



match( restriction, element ) := [ { "rule": restriction, "arg": element } ] if {

   lower(restriction.type) == "any"

   # always true
}


match( restriction, element ) := [ { "rule": restriction, "arg": element } ] if {

   lower(restriction.type) == "prefix"
   is_string(element)
   startswith(lower(element), lower(restriction.data))

}


match( restriction, element ) := [ { "rule": restriction, "arg": element } ] if {

   lower(restriction.type) == "suffix"
   is_string(element)   
   endswith(lower(element), lower(restriction.data))

}


match( restriction, element ) := [ { "rule": restriction, "arg": element } ] if {

   lower(restriction.type) == "suffix"
   is_string(element)
   endswith(lower(element), lower(restriction.data))

}


match( restriction, element ) := [ { "rule": restriction, "arg": element } ] if {

   lower(restriction.type) == "whole"
   is_string(element)   
   lower(element) == lower(restriction.data)

}


match( restriction, element ) := [ { "rule": restriction, "arg": element } ] if {

   lower(restriction.type) == "contains"
   is_string(element)   
   contains(lower(element), lower(restriction.data))

}




match( restriction, element ) := [ { "rule": restriction, "arg": element } ] if {

   lower(restriction.type) == "regex"
   is_string(element)   
   regex.match(restriction.data, lower(element))

}



match( restriction, element ) := [ { "rule": restriction, "arg": element } ] if {

   lower(restriction.type) == "equals"
   is_number(element)   
   element == restriction.data
}


match( restriction, element ) := [ { "rule": restriction, "arg": element } ] if {

   lower(restriction.type) == "gt"
   is_number(element)   
   element > restriction.data
}


match( restriction, element ) := [ { "rule": restriction, "arg": element } ] if {

   lower(restriction.type) == "gte"
   is_number(element)   
   element >= restriction.data
}


match( restriction, element ) := [ { "rule": restriction, "arg": element } ] if {

   lower(restriction.type) == "lt"
   is_number(element)   
   element < restriction.data
}


match( restriction, element ) := [ { "rule": restriction, "arg": element } ] if {

   lower(restriction.type) == "lte"
   is_number(element)   
   element <= restriction.data
}



match( restriction, element ) := [ { "rule": restriction, "arg": element } ] if {

   lower(restriction.type) == "within_range"
   is_number(element)   

   element >= restriction.data[0]
   element <= restriction.data[1]
}

match( restriction, element ) := [ { "rule": restriction, "arg": element } ] if {

   lower(restriction.type) == "outside_range"
   is_number(element)   

   outside_range(element, restriction.data)

}



outside_range( value, range_pair ) := true if {

    value < range_pair[0]
}


outside_range( value, range_pair ) := true if {
    value > range_pair[1]
}


