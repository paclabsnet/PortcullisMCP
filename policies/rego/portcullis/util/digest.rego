package portcullis.digest


import rego.v1



evaluate_response_list( list, trace_id ) := decision if {

    eval_object := {
        "deny" : [ x | 
                    some x in list
                        x.decision == "deny"
                ],
        "allow" : [ x | 
                    some x in list
                        x.decision == "allow"
                  ],
        "escalate" : [ x | 
                    some x in list
                        x.decision == "escalate"
                  ],
        "workflow" : [ x |
                    some x in list
                        x.decision == "workflow"
                  ]
    }
 

    decision := evaluate_results( eval_object, trace_id )

    #
    # general rules:
    # 1) If there are any denies, it's a deny
    # 2) If there are any escalates, but no denies, it's escalate
    # 3) if there are allows, and no deny/escalate results, it's allow
    #
    #  We could respond with all of the denies. For the moment, we'll
    # just respond with the first one.
    #
#    decision := evaluation_ladder( 
#    }


#    decision := escalate_result if {
#        count(deny_list) == 0
#        count(escalate_list) > 0
#        escalate_result := escalate_list[0]
#    }


#    decision := allow_result if {
#        count(deny_list) == 0
#        count(escalate_list) == 0
#        count(allow_list) > 0
#        allow_result := allow_list[0]
#    }



}



evaluate_results( eval_object, trace_id ) := deny_decision if {
    count(eval_object.deny) > 0
    deny_decision := eval_object.deny[0]
}


evaluate_results( eval_object, trace_id ) := escalate_decision if {
    count(eval_object.deny) == 0
    count(eval_object.escalate) > 0
    escalate_decision := eval_object.escalate[0]
}


evaluate_results( eval_object, trace_id ) := workflow_decision if {
    count(eval_object.deny) == 0
    count(eval_object.escalate) == 0
    count(eval_object.workflow) > 0

    workflow_decision := eval_object.workflow[0]
}


evaluate_results( eval_object, trace_id ) := allow_decision if {
    count(eval_object.deny) == 0
    count(eval_object.escalate) == 0
    count(eval_object.workflow) == 0
    count(eval_object.allow) > 0

    allow_decision := eval_object.allow[0]
}


evaluate_results( eval_object, trace_id ) := no_decision if {
    count(eval_object.deny) == 0
    count(eval_object.escalate) == 0
    count(eval_object.workflow) == 0
    count(eval_object.allow) == 0

    no_decision := { "decision": "deny",
                     "reason" : "no rules apply",
                     "trace_id" : trace_id }
}
