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

There are two different implementations of the policy, for the benefit of the reader.

One uses custom rego rules

The other uses a table-driven data element, which does a fair amount of the grunt
work for you, but will probably not scale to the most complex scenarios.

**Tabular -> Custom**
The current setup of the rules is to use the tabular rules first, and if there's no
answer available in the table, delegate to the custom rules.  This gives the policy
architect some flexibility.

**TO REITERATE**
You do *not* have to use the approach I've written to implement policy. You are free
to implement policy any way you want.   The approach I offer makes it straightforward
to offer the escalation and workflow options, but if you don't need those, you can
enable and disable specific MCPs and tools with minimal policy logic.

## Testing

The raygun tests are using the 'tabular' policy path (so using the table-driven policy
found in data.json, in the directory above this one).

## Writing your own policy

The data-driven policy table is probably an easy place to get started. You don't have to
just use the policy table, you can add custom rules to the tabular decision.rego (or
more modularly, call out to custom policy in a different package) .

## Creating your own escalation tokens

For simplicity, and to demonstrate the concept, I just implemented shared-secret JWTs. There's
no reason that the JWTs couldn't use PK signatures, it's just a hassle for me to get that set up
for a PoC.






