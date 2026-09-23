# Specification: Principal Restrictions in Tabular Logic

## 1. Overview
The Portcullis policy engine currently enforces tabular rules using a hardcoded `groups` field inside rules (e.g., `allow` and `escalate` blocks). While this works for standard directory groups, it is too restrictive for enterprise deployments where decisions should be made based on other normalized identity facts, such as department, roles, or custom security classifications.

This feature deprecates and removes the hardcoded `groups` field from tabular rules and replaces it with **`principal_restrictions`**. These restrictions use the exact same format and evaluation logic as `arg_restrictions` but apply to the normalized principal claims in `input.authorization_request.principal`.

Additionally, to provide maximum architectural symmetry, this change introduces **polymorphic rule structures** across the `allow`, `deny`, and `escalate` blocks, enabling them to accept either a singular rule object or an array of rule objects (OR behavior). It also introduces highly precise, **per-rule escalation supersedence** to eliminate security bypasses and over-escalation bugs.

These polymorphic and array structures are supported elegantly by introducing an `ensure_array` utility normalization helper, avoiding complex `is_array` checks or duplicate rules across the policy files.

---

## 2. Goals & Constraints
*   **Decoupled & Generic Identity Attributes:** Any field within `input.authorization_request.principal` (e.g., `roles`, `department`, `acr`, `clearance`, `location`) must be evaluatable.
*   **Absolute Paths:** To reuse the existing traversing engine, key paths for principal restrictions will be absolute relative to `input.authorization_request`, matching the existing convention of `arg_restrictions` (e.g., `"key_path": "principal.groups"`, `"key_path": "principal.department"`).
*   **Polymorphic Rules (Singular/Array):** All blocks (`allow`, `deny`, `escalate`) must support both singular rule objects and arrays of rule objects (implicit OR).
*   **Omitted Means Unrestricted:** If a rule block does not contain a `principal_restrictions` section, it is considered unrestricted (always passes identity validation).
*   **Per-Rule Supersedence:** If a user satisfies a direct `allow` rule, only user-scoped escalation rules are bypassed. Mandatory, argument-scoped escalation rules (e.g., protecting paths like `/var`) are never bypassed.
*   **Zero-Downtime / Backwards-Compatibility:** All existing policy tests must pass with zero modifications to test assertions, proving behavior-preserving compatibility.

---

## 3. Configuration Schema Changes (`policies/rego/data.json`)

All occurrences of the legacy `"groups"` field inside `allow`, `deny`, or `escalate` blocks are migrated to `"principal_restrictions"`.

### Example 1: Standard Wildcard Access
**Before (Legacy):**
```json
"read_file": {
  "allow": {
    "groups": [
      "*"
    ]
  }
}
```
**After (Omitted is Unrestricted):**
```json
"read_file": {
  "allow": {}
}
```

### Example 2: Target-Specific Group Membership
**Before (Legacy):**
```json
"delete_file": {
  "allow": {
    "groups": [
      "admin"
    ]
  }
}
```
**After (New):**
```json
"delete_file": {
  "allow": {
    "principal_restrictions": [
      {
        "type": "contains",
        "key_path": "principal.groups",
        "data": "admin"
      }
    ]
  }
}
```

### Example 3: Escalation with Principal and Argument Restrictions
**Before (Legacy):**
```json
"update_customer": {
  "escalate": [
    {
      "groups": [
        "clerk"
      ],
      "arg_restrictions": [
        {
          "type": "prefix",
          "key_path": "resource.arguments.customer_id",
          "data": ""
        }
      ]
    }
  ]
}
```
**After (New):**
```json
"update_customer": {
  "escalate": [
    {
      "principal_restrictions": [
        {
          "type": "contains",
          "key_path": "principal.groups",
          "data": "clerk"
        }
      ],
      "arg_restrictions": [
        {
          "type": "prefix",
          "key_path": "resource.arguments.customer_id",
          "data": ""
        }
      ]
    }
  ]
}
```

---

## 4. Policy Rules Changes (OPA Rego)

### A. Utility Helpers (`policies/rego/portcullis/util/util.rego`)

We define highly reusable checks for evaluating `principal_restrictions` exactly like `arg_restrictions`. We also introduce `ensure_array` to normalize rules inputs:

```rego
# Helper to normalize singular or array values to an array
ensure_array(val) := val if {
   is_array(val)
} else := [val]

#
# returns true if any of the principal restriction requirements are met
#
any_principal_restriction_rule_honored( principal_restriction_rule_array, request_body) := true if {
   some restriction in principal_restriction_rule_array
      principal_restriction_honored( restriction, request_body )
} else := no_principal_restrictions_to_honor( principal_restriction_rule_array )

#
# returns true if there are no principal restrictions to evaluate
#
no_principal_restrictions_to_honor( principal_restriction_rule_array ) := true if {
   count(principal_restriction_rule_array) == 0
} else := false

#
# check one specific principal_restriction, which can be several sub-restrictions ANDED together
#
principal_restriction_honored( restriction, request_body) := true if {
  rule_element_matched_list := find_principal_restriction_matches_for_ANDED_group( restriction, request_body )
  count(rule_element_matched_list) > 0
} else := false   

find_principal_restriction_matches_for_ANDED_group( restriction, request_body ) := rule_element_matched_list if {
   lower(restriction.type) == "and"
   rule_element_matched_list := find_every_principal_restriction_rule_matches( restriction.list, request_body)
} else := find_principal_restriction_matches_for_single_element( restriction, request_body)

find_principal_restriction_matches_for_single_element( restriction, request_body ) := rule_element_matched_list if {
  key_path_array := split(restriction.key_path, ".")
  element := traverse_json( request_body, key_path_array)
  rule_element_matched_list := rule_match.match(restriction, element)
} else := []

find_every_principal_restriction_rule_matches( principal_restriction_rule_array, request_body ) := rule_element_matched_list if {
  rule_element_matched_list := [ rule_element_item | 
                                 some restriction in principal_restriction_rule_array
                                    child_rule_element_matched_list := find_principal_restriction_matches_for_single_element( restriction, request_body)
                                    count(child_rule_element_matched_list) > 0
                                    rule_element_item := child_rule_element_matched_list[0]
                      ]
  count(rule_element_matched_list) == count(principal_restriction_rule_array)
} else := []

#
# Decoupled checker helpers
#
principal_restrictions_ok(request, rules) := true if {
   not "principal_restrictions" in object.keys(rules)
} else := any_principal_restriction_rule_honored(rules.principal_restrictions, request)

arg_restrictions_ok(request, rules) := true if {
   not "arg_restrictions" in object.keys(rules)
} else := util.any_arg_restriction_rule_honored(rules.arg_restrictions, request)

has_any_restrictions(rules) := true if {
   "principal_restrictions" in object.keys(rules)
} else := "arg_restrictions" in object.keys(rules)
```

### B. Polymorphic Rule Checking (`policies/rego/portcullis/util/allowdeny.rego`)

We remove the legacy `groups` checks and replace them with a unified polymorphic rule check using `ensure_array`:

```rego
# Evaluates criteria against allowed or denied blocks supporting polymorphism
request_matches_rule_criteria( request, rules ) := true if {
   some rule in util.ensure_array(rules)
   request_matches_single_rule_criteria( request, rule )
}

# Core evaluation of a single rule block
request_matches_single_rule_criteria( request, rule ) := true if {
   util.principal_restrictions_ok(request, rule)
   util.arg_restrictions_ok(request, rule)
   util.has_any_restrictions(rule)
}
```

### C. Base Criteria & Per-Rule Supersedence (`policies/rego/portcullis/util/escalate.rego`)

We evaluate `escalate` rules base criteria and per-rule active rule filtering using `ensure_array`:

```rego
# Evaluate if request matches the base criteria of any escalation path
request_matches_base_criteria( request, rules ) := true if {
   some rule in util.ensure_array(rules)
   request_matches_base_criteria_rule( request, rule)
}

# Base criteria matching for a single escalation rule
request_matches_base_criteria_rule( request, rule ) := true if {
   util.principal_restrictions_ok(request, rule)
   util.arg_restrictions_ok(request, rule)
   util.has_any_restrictions(rule)
}

# An individual escalation rule is superseded if:
# 1) It has user-specific restrictions (principal_restrictions)
# 2) AND the user fully satisfies an allow rule.  
#
# The subtle implication of this is that you (the rule author) need to be 
# careful about how you craft your allow rules so they aren't too broad, or they
# might supersede an escalate rule
#
# The precedence is: 
#  1. if the deny rule matches, the deny rule wins
#  2. escalate wins if it has an argument restriction
#  3. workflow 
#  4. allow
#  5. escalate if there's a principal restriction, but no argument restriction
#  6. deny if there's no match at all (fail closed)
#
#
#  
escalate_rule_superseded_by_allow( request, rule, allow_rules ) if {
   "principal_restrictions" in object.keys(rule)
   allowdeny.request_matches_rule_criteria( request, allow_rules )
}

# Find all escalation rules that are matched AND NOT superseded
active_escalation_rules( request, rules_escalate, rules_allow ) := [ rule |
   some rule in util.ensure_array(rules_escalate)
   request_matches_base_criteria_rule( request, rule )
   not escalate_rule_superseded_by_allow( request, rule, rules_allow )
 ]
```

### D. Decision Rule Updates (`policies/rego/portcullis/tabular/decision.rego`)

We update the `tabular/decision.rego` logic to query `active_escalation_rules`:

```rego
# Retrieve active, non-superseded escalation rules
active_escalation_rules := escalate.active_escalation_rules(
    input.authorization_request, 
    rules_section.escalate, 
    rules_section.allow
)

# Decision additions now rely on the active rule count:
response_list contains { "decision" : "allow",
			  "reason" : "Allowed by escalation token",
			  "trace_id" : trace_id } if {

				not rules_section.escalate == null
				count(escalation_grant_list) > 0
				
				# Check that we have at least one active escalation path
				count(active_escalation_rules) > 0
				escalate.request_matches_escalation_criteria( 
						input.authorization_request, 
						rules_section.escalate, 
						escalation_grant_list )
			  }

response_list contains {
				"decision" : "escalate",
			  	"reason" : "Request is not approved, but can be escalated",
				"escalation_scope" : escalation_scope,
			  	"trace_id" : trace_id } if {

					not rules_section.escalate == null
					
					# Check that we have active escalation paths
					count(active_escalation_rules) > 0

					# Ensure escalation criteria are not already fully met by grants
					not escalate.request_matches_escalation_criteria( 
							input.authorization_request, 
							rules_section.escalate, 
							escalation_grant_list )

					escalation_scope := escalate.find_matching_escalation_criteria( 
							input.authorization_request, 
							rules_section.escalate,
							escalation_grant_list)
				}
```

---

## 5. Verification Plan
1.  **Local OPA Build compilation:** Run `./build.sh` (or `opa build .`) in `policies/rego` to guarantee that all modified Rego rules compile flawlessly.
2. **New Test Cases:** - develop test cases to exercise and verify the decision hierarchy (deny, escalate w/arg_restrictions, allow, escalate with principal_restrictions, deny [if no rules apply]
3.  **Raygun Suite execution:** Run `raygun` suite tests against `tabular.raygun`. Since this is behavioral refactoring, **every single test case must continue to pass successfully** with zero modifications to test structures, validating backwards-compatibility and zero regressions.
