# Principal Restrictions in Tabular Logic Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Provide full Attribute-Based Access Control (ABAC) capabilities to the OPA policy engine by replacing legacy hardcoded "groups" fields with absolute, generic "principal_restrictions".

**Architecture:** Polymorphic rules are implemented for `allow`, `deny`, and `escalate` blocks supporting both single-object and array structures via the `ensure_array` helper. Active escalation paths are filtered per-rule to prevent security bypasses and over-escalation.

**Tech Stack:** OPA Rego, JSON

**Spec:** `docs/development/specs/2026-09-22-principal-restrictions-tabular-logic.md`

## Global Constraints
*   **Zero-Downtime Migration:** All existing access patterns must remain identical.
*   **Strict Security defaults:** All blocks that specify no restrictions are unrestricted, but missing blocks fail-securely to deny.
*   **Behavioral Verification:** Existing OPA test suites must continue to pass successfully.

## Review Focus
*   **Array normalization safety:** Verifying that the `ensure_array` helper safely converts single values without any OPA runtime failures.
*   **Accidental Supersedence Bypasses:** Verifying that a broad `allow` rule does not accidentally bypass argument-scoped protection like `/var` (which is guaranteed by the key check for `principal_restrictions`).

---

### Task 1: Update Configuration Schema (`data.json`)

**Files:**
*   Modify: `policies/rego/data.json`

**Interfaces:**
*   Produces: Updated OPA static policies schema replacing all `"groups": [...]` keys with `"principal_restrictions": [...]` where needed, and removing `"groups": ["*"]` blocks in favor of unrestricted empty objects `{}`.

- [ ] **Step 1: Replace wildcard groups in `data.json`**
  Modify the `allow` block for `read_file`, `read_text_file`, `read_media_file`, `read_multiple_files`, `edit_file`, `create_directory`, `list_directory`, `list_directory_with_sizes`, `directory_tree`, `move_file`, `search_files`, `copy_file`, `search_within_files`, `get_file_info`, `list_allowed_directories`, and `query_order` to use empty objects `{}` instead of `"groups": ["*"]`.

- [ ] **Step 2: Replace specific group constraints with principal_restrictions**
  Modify specific group constraints in `delete_file`, `get_customer`, `update_customer`, and `update_order_status` to use `"principal_restrictions"` matching the absolute path `"principal.groups"`.

- [ ] **Step 3: Verify syntax of `data.json`**
  Ensure the JSON continues to parse cleanly.

---

### Task 2: Implement Utility Helpers in `util.rego`

**Files:**
*   Modify: `policies/rego/portcullis/util/util.rego`

**Interfaces:**
*   Produces: Normalization helper `ensure_array`, generic matching functions `any_principal_restriction_rule_honored`, `principal_restrictions_ok`, `arg_restrictions_ok`, and `has_any_restrictions`.

- [ ] **Step 1: Add the `ensure_array` utility normalization helper**
  Add the array-normalization rule to `util.rego` (as specified in Section 4.A of the Spec).

- [ ] **Step 2: Add principal_restrictions parser and matching logic**
  Add the complete principal restriction matching functions and decoupled checker helpers (as specified in Section 4.A of the Spec).

- [ ] **Step 3: Run local build compilation check**
  Run: `opa build policies/rego`
  Expected: PASS

---

### Task 3: Refactor Allow/Deny Rules to support Polymorphism

**Files:**
*   Modify: `policies/rego/portcullis/util/allowdeny.rego`

**Interfaces:**
*   Consumes: `util.ensure_array`, `util.principal_restrictions_ok`, `util.arg_restrictions_ok`, and `util.has_any_restrictions`.
*   Produces: Polymorphic `request_matches_rule_criteria` supporting both singular rule objects and rule arrays via `ensure_array`.

- [ ] **Step 1: Rewrite rule criteria evaluation in `allowdeny.rego`**
  Update `request_matches_rule_criteria` to implement polymorphic array and single object matching using `ensure_array` (as specified in Section 4.B of the Spec).

- [ ] **Step 2: Run local build compilation check**
  Run: `opa build policies/rego`
  Expected: PASS

---

### Task 4: Refactor Escalate Rules & Per-Rule Supersedence

**Files:**
*   Modify: `policies/rego/portcullis/util/escalate.rego`

**Interfaces:**
*   Consumes: `util.ensure_array`, `util.principal_restrictions_ok`, `util.arg_restrictions_ok`, `util.has_any_restrictions`, and `allowdeny.request_matches_rule_criteria`.
*   Produces: Polymorphic base criteria matching and the per-rule `active_escalation_rules` filter.

- [ ] **Step 1: Rewrite `request_matches_base_criteria` for polymorphism**
  Update base matching rules in `escalate.rego` using `ensure_array` (as specified in Section 4.C of the Spec).

- [ ] **Step 2: Implement `escalate_rule_superseded_by_allow` and `active_escalation_rules`**
  Add the per-rule supersedence rules utilizing `ensure_array` (as specified in Section 4.C of the Spec).

- [ ] **Step 3: Run local build compilation check**
  Run: `opa build policies/rego`
  Expected: PASS

---

### Task 5: Integrate Active Rule Checks inside `decision.rego`

**Files:**
*   Modify: `policies/rego/portcullis/tabular/decision.rego`

**Interfaces:**
*   Consumes: `escalate.active_escalation_rules`.
*   Produces: Refactored decision rules for allowed-by-token and escalatable scenarios.

- [ ] **Step 1: Integrate `active_escalation_rules` query**
  Update allow-by-token and escalate rules in `decision.rego` to enforce active rulesets (as specified in Section 4.D of the Spec).

- [ ] **Step 2: Run local build compilation check**
  Run: `opa build policies/rego`
  Expected: PASS

---

### Task 6: Run Policy Verification Test Suite

**Files:**
*   Verify: `policies/rego/test/tabular.raygun`

**Interfaces:**
*   Consumes: Fully compiled OPA bundle with new rules and configuration data.

- [ ] **Step 1: Re-build policy bundle**
  Run: `cd policies/rego && ./build.sh`
  Expected: Bundle builds successfully.

- [ ] **Step 2: Execute Raygun policy tests**
  Run tests using the project's Raygun test runner.
  Expected: 100% of the tabular policy tests continue to PASS successfully with zero modifications to test cases.
