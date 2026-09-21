# Enhanced Escalation Tokens: Group Membership Grants

## Problem

The current escalation model assumes the requesting user already belongs to a group
that the policy allows to escalate. This does not support separation-of-duties
scenarios where:

- The requesting user does NOT have the necessary group membership
- A separate approver (or M-of-N approval workflow) grants temporary elevated
  privilege for a specific operation

The goal is to allow third-party workflow approval systems to work with Guard to
mint escalation tokens that carry special group privileges, so that an agent's
effective group membership can be temporarily increased for a specific tool/service
call by the presence of appropriate escalation tokens.

## Concept

### A. Groups as an optional escalation token claim

Add an optional `groups` field to escalation tokens. When an escalation token
carries a `groups` claim, those groups are temporarily added to the user's group
set for the duration of that specific tool/service call evaluation.

### B. Policy evaluation with augmented groups

If a user would normally be denied access to a tool/service call based on their
normal group membership, but they possess an escalation token that includes the
matching tool/service and a `groups` claim, the policy is re-evaluated as if the
user has the enhanced group membership:

- If the escalation token grants access to a service/tool with a group, and the
  policy for that group/service/tool is `allow`, it is accepted as-is.
- If the policy for that group/service/tool is `escalate`, the argument parameters
  in the escalation token are verified against the policy's arg restriction rules.

This gives flexibility to support both "wildcard" approvals (token grants allow
with no arg restrictions) and "we're granting enhanced privilege for a very
specific request" (token grants escalate with matching arg restrictions).

### Concrete example

User's directory groups: `[A, B]`

User calls MCP tool `Filesystem`, service `Read`, with three escalation tokens:
1. service=Filesystem, tool=Read, groups=[Admin]
2. service=Filesystem, tool=Write, groups=[Admin]
3. service=Filesystem, tool=Read, groups=[B]

Tokens 1 and 3 match the current call (same service + tool). Token 2 does not
match (wrong tool) and contributes nothing. Effective groups for this evaluation:
`[A, B, Admin]`

`deny` decisions are not overridable by escalation token groups — deny is always
terminal regardless of what tokens the user holds.

## Security Constraints

- The `groups` claim MUST NOT be settable via the Guard approval UI. Allowing a
  user to self-grant group membership through Guard would defeat the purpose.
- Groups in escalation tokens MUST originate from a trusted third-party workflow
  system (e.g., a separation-of-duties approval tool, an M-of-N signing process).
- The third-party system deposits the pre-minted JWT via Guard's existing
  `POST /token/deposit` machine API, which is protected by bearer token auth.
- Keep and OPA are the ultimate arbiters of trust. Guard does not re-validate the
  groups claim — the security guarantee comes from restricting who can call the
  deposit API, not from Guard inspecting token contents.

## Tasks

1. **`internal/shared/types.go`** — add `Groups []string` (omitempty) to
   `EscalationRequestClaims` so the deposit endpoint can parse it from the
   incoming JWT

2. **`internal/guard/config.go`** — add `Groups []string` (omitempty) to
   `portcullisClaims`

3. **`internal/guard/server.go`**
   - `issueEscalationToken`: add `groups []string` parameter; include in
     `portcullisClaims` when non-empty
   - `handleTokenDeposit`: pass `claims.Groups` to `issueEscalationToken`
   - Guard approval UI (`handleApproveAction`): does NOT pass groups — groups
     remain zero-value for all human-approved tokens

4. **`internal/gate/api.go`** — add `Groups []string` (omitempty) to the local
   `portcullisClaims` struct so Gate can read groups out of escalation tokens
   when forwarding to Keep

5. **OPA/Rego policy (`policies/rego/`)**
   - Add group augmentation logic to the tabular decision module:
     1. For each escalation token in `context.escalation_tokens`, check if
        `token.portcullis.services` and `token.portcullis.tools` match the
        current `action.service` / `action.tool`
     2. If matched, union `token.portcullis.groups` into the effective group set
     3. Evaluate allow/escalate/deny using the effective group set instead of
        `principal.groups` directly
   - Arg restriction matching for `escalate` continues to use existing logic
     (token args must match current call args)
   - `deny` rules ignore augmented groups — deny is unconditional

6. **Demo / test tooling** — add a helper script or `make` target that mints a
   demo escalation JWT with a `groups` claim and deposits it via
   `POST /token/deposit`; add tabular test cases covering:
   - Token with groups grants access that normal groups would deny
   - Token for wrong tool does not contribute groups
   - Deny is not overridable by token groups

## Open Questions

- Should Keep validate that the `groups` in the escalation token are a subset of
  groups that exist in the directory, or is any string value acceptable?
- Should there be a dedicated audit log entry for group-augmented decisions, to
  make separation-of-duties grants visible in compliance reporting?
- What is the expected token TTL for group-bearing tokens — same as normal
  escalation tokens, or configurable per-deposit?
