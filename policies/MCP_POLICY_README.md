# AI Policy

This is where some example AI policies have been implemented.

We've implemented example Rego policies.  Permit will come later. It may be difficult to implement escalation in Cedar,
TBD.

## Vision
The concept here is that you will set up a PDP (Policy Decision Point) that will be used by Portcullis to validate
AI Agent requests. The format of the request and response JSON documents are defined elsewhere, and should be
 consistent across any PDP you might implement. the only different would be in some of the wrapping that Portcullis
 might
use for different PDPs.

You should assemble the types of policy your organization wishes to enforce upon the agents. And then write the
appropriate
policy enforcement logic in the language of your PDP of choice.  It is
our belief that using this PDP-based approach allows for more scalability and operational discipline than using some
sort of embedded policy model.

The format of the input and output from Portcullis to and from the PDP is standardized. There may be some different
wrapping
needed for different PDPs, but the guts should remain the same.

## Escalation
the trickiest concept in Portcullis is probably escalation. We have chosen to use JWTs to represent the data that tells
the PDP that a particular request is 'blessed' by the user (or the organzation). JWTs provide several benefits:
expiration,
various signing strategies, well-supported.  The `portcullis` claim in the JWT is a JSON object that represents details
about a request (or a set of very closely related requests) that would normally be forbidden, but are temporarily
allowed.

### Escalation examples
It's probably fine for the agent to use an MCP to read from certain project directories on your computer. Probably not
fine for the
agent to read from most other directories. For example, you may not normally want
your agent to be reading from `/var/log` on a server. But sometimes it might be the right thing. So you can create a JWT
that
includes a `portcullis` claim that elaborates on the set of MCP services, tools and arguments that are approved.

## Sample Policy
The Rego samples are an effort to think through some of the common use cases. The goal here is to give you a set of
patterns that you can use to implement the policy that your organization needs.  We wrote the Rego policies in two
different styles, for the implementor's benefit.

## PDP Neutral
The idea is that we don't require the use of a particular PDP.  As long as the PDP handles:
1. JWT validation & parsing
2. Sophisticated response objects (so you can return more than just 'allow', 'deny')

You can use a JWT-based strategy to allow users to grant the Agent specific rights to perform
specific actions on the user's behalf.

The easiest PDP to get set up and running to do this work is OPA, but if that's no the right choice
for you, it should be straightforward to adapt.

## Using OPA

If you do want to use OPA, these tests use the open source tool 'raygun' https://github.com/paclabsnet/raygun
to validate the behavior of the policy logic

For the benefit of the reader, we offer a table-driven data element, which does a fair amount of the grunt work for you, but will probably not scale to the most complex scenarios.

**Tabular -> Custom**
The current setup of the rules is to use the tabular rules first, and if there's no
answer available in the table, delegate to the custom rules.  This gives the policy
architect some flexibility.

**TO REITERATE**
You do *not* have to use the approach I've written to implement policy. You are free
to implement policy any way you want.   The approach I offer makes it straightforward
to offer the escalation and workflow options, but if you don't need those, you can
enable and disable specific MCPs and tools with minimal policy logic.

### How it Works
Basically, the first "clever" bit is in the `arg_restrictions` JSON objects, which describe tests in JSON. We apply these tests to incoming MCP requests, and if a test matches the input, then the rule (allow/deny/escalate) applies.   Since it's conceivable that more than one test (and more than one rule) can be true,
we use a simple guide of:   any deny == deny. If no deny, any allow == allow.  If no deny or allow, any escalate == escalate.  And finally, to fail closed, if there are no rules that apply, it's a deny.

#### How escalation works
But then there's the JWTs that can be attached to the input.  If you decode the JWTs, you'll find... more `arg_restrictions` .  And in the tabular logic, if a test from `escalate` ruleset matches, there's a second test, where we check to see if there's a test in the JWT that *also* matches.  If there is, then instead of an `escalate`, we treat it as an `allow`.  

Why?  Because the presence of the test in the signed JWT is evidence that a human approved the test. which is the whole point of this exercise.  

"But can the AI reuse that same token to cause mischief". **only if the human is deliberately expansive**. 

Consider a scenario:

**Updates to a customer's name require escalation**

The AI attempts to rename Customer 123 to 'Joe Williams'. This hits a test in the `escalate` ruleset for the `update_customer` MCP tool. But the rule isn't (typically) specifically about Customer 123!  It's about *any* customer. Customer 123 is part of the set of 'any', so the system returns `escalate`. 

Now a human sees this escalation request, and approves it. But what has the human approved? a test that is specifically about using the `update_customer` tool on `customer_id: 123` .  If the AI tried to use this token to rename customer 222, it wouldn't work! Because the test in the JWT is specifically about customer_id 123.  

Could the AI rename customer 123 a second time?  Yes.  Unless the JWT is revoked, or expires.   But the AI can't rename any other customer. 

**You said something about 'expansive'**

The human doesn't have to limit the test to customer_id: 123.  They can (and sometimes should) make the approval test broader.  Conceivably even broadening the scope to *any* customer.  That's probably a good idea sometimes (for example, changing the status of a bunch of orders from 'awaiting pickup' to 'shipped' , without a specific escalation for each order).

So the human has the choice - limit the blast radius, or make it wider.  Their choice.

#### Special Case: the 'any' test

The one counterintutive test is the 'any' test.  If you set the escalate ruleset to include escalate for *any* customer_id, well, then, if the human approves it, they're approving a test that will mirror that *any*. Which means that any customer id will be accepted.

There's an argument that at Portcullis-Guard, we should replace *any* with a more restrictive test instead. That is a discussion worth having.  


## Testing

The raygun tests are using the 'tabular' policy path (so using the table-driven policy
found in data.json, in the directory above this one).

## Writing your own policy

The data-driven policy table is probably an easy place to get started. You don't have to
just use the policy table, you can add custom rules to the tabular decision.rego (or
more modularly, call out to custom policy in a different package) .

## Creating your own escalation tokens

For simplicity, and to demonstrate the concept, my examples use shared-secret JWTs. There's
no reason that the JWTs couldn't use PK signatures. If you look at mock-idp.dev, you'll be able to create JWTs signed by mock-idp.dev's private keys. We already use this mechanism for some of the oidc-tokens, but with some modest code updates, we can make Guard sign the e-tokens with a private key.  






