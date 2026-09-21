# Demo Improvements


We need to update the demo infrastructure in the following ways:


1) add an additional pending order to the existing mock demo set, so we can demonstrate that human authorization of one order doesn't allow a change to another.

2) We need to add multiple demo users with different group memberships, so we can demonstrate that policies can vary from group to group.

3) We need to group membership as an optional element to the escalation token.

4) We need to change the policy logic so that even if a user would normally be denied access a tool / service call (based on their normal group membership) but possessed an escalation token that includes the tool / service and an appropriate group membership, it can be used to validate escalation

Note on 4: if the escalation token grants access to a service / tool with a group, and the policy for that group, service and tool is "allow" then it accepts it as is.   If the policy for that group, service and tool is escalate, it would verify that the argument parameters in the escalation token match the policy rules.  This gives us the flexibility to support "wildcard" approvals as well as "we're granting enhanced privilege for a very specific request"

  

