package portcullis.gate_static_config


import rego.v1


policy := mcp_policy if {

   print("#DEBUG: gate_static_config: resource: ", input.resource)
   print("#DEBUG: gate_static_config: config: ", data.portcullis.gate_static_policy)

   input.resource in object.keys(data.portcullis.gate_static_policy)

   mcp_policy := data.portcullis.gate_static_policy[input.resource]

}



default policy := {}