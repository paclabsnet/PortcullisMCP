# Recently Completed Work


### Task: Fix Escalation
- Modify Guard to hold the escalation tokens in some sort of in-memory keystore, ideally a distributed keystore
- Modify Gate to detect when Keep has responded with an escalation event, and set it to call Guard on the next outbound MCP call to collect any new e-tokens
- Use the UserIdentity.UserId field from the JWT as the key. 



## Implementation Notes



### Fix Escalation 
  So the proposed implementation is:
  - Gate: An in-memory map[string]PendingEscalation in Gate (keyed by ServerName+ToolName or EscalationID)
    - this pending escalation map should be protected by mutex
  - Gate: When the Agent requests a particular service/tool, it checks the PendingEscalation map to see if that server/tool
    has a pending e-Token.  If it does, it calls /token/claim with the JTI of that pending escalation token.  
  - Guard has three new endpoints:
    - `/token/unclaimed/list` . Caller provides a UserID, receives back a list of all unclaimed tokens for that User
    - `/token/deposit` . Caller provides a signed pending JWT and a UserID.  Guard will validate the pending JWT, before creating the signed escalation token, and adding it to the unclaimed list.
    - `/token/claim` . Caller provides the unique id of the token (jti?), which removes it from the unclaimed list. You only get to claim
      a token once. Put a mutex around it, to avoid any risk of multiple claims in parallel.  This returns the signed e-Token as the response.
      - note that it's possible that the user never approved the escalation request, in which case `/token/claim` would return an empty response
  - Guard holds the tokens in a simple store (even in-memory with a TTL is fine) until claimed
  - Guard: when it receives approval from the `/approve` endpoint, it must ensure that the JTI from the pending escalation request is copied to the
           approved claim.  And of course, once approved, the new e-Token must be added to the `/token/unclaimed/list`
  - Guard holds the unclaimed tokens in a list keyed by UserID, which will handle both the scenario of user-based approvals through the Guard UI and remote admin approvals (like servicenow).
    - The value of that record will be the list of unclaimed e-Tokens for the given UserID
    - This list should be cleaned up on a regular basis (configurable) to remove stale tokens (base on token expiration date if provided, a configurable duration otherwise)
  - Gate may call `/token/unclaimed/list` to check if there are tokens that have been approved, but were not previously known to Gate.
    - Unknown tokens can happen when the e-Token is approved by a remote workflow, such as servicenow.
    - This will be called periodically by Gate (at a configured frequency), to claim each of them, and update the 'current' list of approved e-Tokens
      - when tokens are claimed, they need to be removed from the pending escalation list (based on the matching JTI)

  - in a real enterprise, this would be a distributed cache, perhaps Redis, but that's overkill for now
  - Gate will need configuration data for `guard.endpoint` to know where to call to claim tokens and to list them
  - Gate should use a bearer token or mTLS to authentiate to Guard for `/token/unclaimed/list` . It does not not need auth for `/token/claim` IMO because the attacker would have to already know the JTI, which is nearly impossible unless something in the network is compromised.  Even so, it's not a huge problem. We'll include a comment indicating that this is why we don't require an auth header.
  - ServiceNow or any remote workflow system will call `/token/deposit` at Guard when a workflow approves a new token. This will require authentication, and may be distinct from the way we authenticate `/token/unclaimed/list`. For now, let it be the same.
  - We will note in the code comments that the JTI being shared between the pending escalation JWT and the e-Token JWT are the same for correlation purposes, it is not a bug, and they have different issuers, so it's not violating the spec.

The flow will be:
   1. User -> Agent -> Gate: `read_file("/etc/shadow")`
   2. Gate -> Keep: "Can John do this?"
   3. Keep -> PDP: "Can John do this?"
      3.1: Allow - Keep sends the MCP request on to the target
      3.2: Deny - Keep sends a denial message back to Gate for the user
      3.3: Escalate: Keep looks at config and chooses the appropriate approval workflow (ServiceNow, URL, etc) 
        3.3.1 The ServiceNow path is getting very complicated, because just because a request *can* be escalated doesn't mean it *should* be escalated, and we want user approval for that. We will probably have to send a message to the user with a URL that allows the user to request approval through ServiceNow, along with information about the claims requesed.  ServiceNow or other workflow systems would have to have that capability.  Once the request was approved at ServiceNow, ServiceNow would then post the pending escalation token (signed by Keep) to Guard via `/token/deposit` for the known UserID, which is similar to `/approve` but not tied into a web form. Guard would then create the approved escalation token JWT, in a consistent manner with how the `/approve` endpoint works.  In essence, ServiceNow calling `/token/deposit` represents approval, but in a form that is suitable for use as an API.
        3.3.2 For the user-approval workflow URL path, Keep generates:
           - the pending escalation JWT with a JTI
           - the approval URL for the user to use to approve the token at Guard
   4. Keep -> Gate: (Assuming the interesting escalation path) 202 Escalation Required (ID: 123), and includes the Approval URL and instructions to the agent to show the URL to the user, and how long the pending token will live before being purged (pulled from configuration)
      4.1 Gate sees a code in the response that indicates that escalation is required, and caches the pending e-token JTI in its pending escalation list as described in the implementation section above
   5. Gate -> Agent: sends the approval URL and instructions
   6. Agent -> User: shows the URL and instructions
   7. User -> Guard:  User clicks on the approval URL and reviews at Guard.
      7.1 If the user doesn't approve, nothing happens
      7.2 If the user approves, Guard creates and signs a new  escalation token and adds it to the unclaimed token list for that UserId
        7.2.1: IMPORTANT - the new escalation token (e-Token) must have the same JTI as the pending token, or the Gate won't be able to find it
   8. User -> Agent -> Gate:  `read_file("/etc/shadow"`)
   9. Gate looks at local pending escalation list, to see if any of the pending escalations match that service and tool
      9.1 if it finds one, it calls `/token/claim` at Guard to claim it officially, and remove it from the pending list
      9.2 if a request comes from the agent that doesn't match a pending escalation service/tool, we'll assume that none exists, and proceed on to step 10.  
      *note*: It is perfectly fine for Gate to claim multiple tokens if they match the server/tool being used. Keep passes all of those tokens to the PDP, and the PDP handles multiple tokens well
  10. Gate -> Keep: "Can John do this?" - but now (optionally) with a new e-Token
  11. Keep -> PDP: "Can John do this?" - optionally with new token attached
  12. PDP -> Keep:
      12.1: Allow - same as 3.1
      12.2: Deny - same as 3.2
      12.3: Escalate, which triggers the escalation workflow from step 3.3 above.
         - This could create a loop where somewhow the user isn't getting the right token created, so he or she can never get the work done. 
           That is a problem for another day since this is user-driven, and not a runaway process endless loop.





### Task: Identity at Keep - Demo vs Real
The default behavior for Keep should be to ignore any identity information sent by Gate except maybe UserId, when the source is `os`.
When Keep is in demo mode, it will accept forged identity information. It should generate an error message each time it does this unless
the config says to accept forged identities (dependent on demo mode)

- high priority



### Task: Keep should not follow redirects when calling MCPs via HTTP
- SSRF protection
- optionally: block RFC 1918, loopback, and link-local ranges at the HTTP client level for backend calls

- medium priority
