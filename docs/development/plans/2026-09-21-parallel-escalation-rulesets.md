# Parallel Escalation Rulesets

## Problem

The current policy schema allows exactly one `escalate` section per tool. This means a tool
can only have a single escalation path — one group of users who are eligible to request
escalation, with one set of arg restrictions.

This is too restrictive for real-world scenarios where different groups have different
escalation needs for the same tool. For example:

- `update_customer` might allow **clerks** to escalate for any customer_id, while
  **developers** can escalate only for customer_ids above a threshold (test accounts)
- `update_order_status` might allow **developers** to escalate for routine orders, while
  **managers** can escalate for high-value orders with a different arg restriction

With a single `escalate` object, these cannot be expressed without collapsing the groups
into one set and losing the per-group arg restriction semantics.

## Solution

Change the `escalate` value in the policy schema from a single object to an **array of
escalate objects**. Each element defines an independent escalation path: its own `groups`
and/or `arg_restrictions`. Any element whose criteria the user satisfies makes them
eligible for escalation (or grants allow when matched by a token).

### Schema — before

```json
"escalate": {
  "groups": ["clerk"],
  "arg_restrictions": [...]
}
```

### Schema — after

```json
"escalate": [
  {
    "groups": ["clerk"],
    "arg_restrictions": [...]
  },
  {
    "groups": ["developer"],
    "arg_restrictions": [...]
  }
]
```

A single-element array is equivalent to the old object form.

## Concrete Example

`update_customer` with two independent escalation paths:

```json
"update_customer": {
  "allow": {
    "groups": ["admin"]
  },
  "escalate": [
    {
      "groups": ["clerk"],
      "arg_restrictions": [
        { "type": "gte", "key_path": "resource.arguments.customer_id", "data": 0 }
      ]
    },
    {
      "groups": ["developer"],
      "arg_restrictions": [
        { "type": "gte", "key_path": "resource.arguments.customer_id", "data": 9000 }
      ]
    }
  ]
}
```

- A **clerk** can escalate for any customer_id >= 0
- A **developer** can escalate only for customer_id >= 9000 (test account range)
- An **admin** gets `allow` directly — no escalation needed
- Anyone else gets `deny`

## Evaluation Semantics

The priority chain (deny > escalate > allow) is unchanged. What changes is that
`request_matches_base_criteria` and `find_matching_escalation_criteria` now iterate over
the array and succeed if **any** element matches.

### Base criteria (escalate eligibility)

The user is eligible to request escalation if they satisfy at least one element of the
`escalate` array. First-match wins; all matching elements contribute to the
`escalation_scope` returned to the caller.

### Escalation token matching

An escalation token grants `allow` if it satisfies `request_matches_escalation_criteria`
against **any** element of the array. The existing per-element logic is unchanged; the
array iteration is the only addition.

### `user_superseded_by_allow` guard

The existing guard that prevents an escalate response when the user already satisfies
the allow rule must check whether **any** escalate element has a `groups` key (not just
the single object). The guard fires if at least one element has `groups` AND the user
satisfies the allow rule.

## Tasks

1. **`policies/rego/data.json`** — migrate all `escalate` objects to single-element
   arrays; add a second escalation path to `update_customer` and `update_order_status`
   as a demonstration

2. **`policies/rego/portcullis/util/escalate.rego`**
   - `request_matches_base_criteria(request, rules_array)` — iterate over `rules_array`;
     return true if any element satisfies the existing per-element logic
   - `find_matching_escalation_criteria(request, rules_array, grants)` — iterate; collect
     matching escalation claims across all matching elements
   - `request_matches_escalation_criteria(request, rules_array, grants)` — iterate;
     return true if any element is satisfied by a grant

3. **`policies/rego/portcullis/tabular/decision.rego`**
   - Update `user_superseded_by_allow` to check `some e in rules_section.escalate;
     "groups" in object.keys(e)` instead of `"groups" in object.keys(rules_section.escalate)`

4. **`policies/rego/test/tabular.raygun`** — add test cases:
   - clerk escalates `update_customer` with low customer_id (matches element 0)
   - developer escalates `update_customer` with high customer_id (matches element 1)
   - developer denied `update_customer` with low customer_id (matches neither element)
   - escalation token for element 0 does not grant allow on element 1's arg range

## Closed Questions

- **Should `deny` also become an array?** No. Deny is already the default outcome, so
  multiple independent deny conditions add no value. A single deny object is sufficient.
- **Should `escalation_scope` include all matching elements or just the first?** Just the
  first. The scope is used to mint a token describing what the approver should authorize.
  The first matching element provides exactly that; additional matching elements are
  alternative paths to the same outcome and add no value to the approver.
