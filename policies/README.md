# AI Policy

This is where some example AI policies have been implemented. 

We've implemented example Rego policies.  Permit will come later. It may be difficult to implement escalation in Cedar,
TBD.  

## Vision
The concept here is that you will set up a PDP (Policy Decision Point) that will be used by Portcullis to validate 
AI Agent requests. The format of the request and response JSON documents are defined elsewhere, and should be
 consistent across any PDP you might implement.  the only different would be in some of the wrapping that Portcullis might
use for different PDPs.

You should assemble the types of policy your organization wishes to enforce upon the agents. And then write the appropriate
policy enforcement logic in the language of your PDP of choice.  It is 
our belief that using this PDP-based approach allows for more scalability and operational discipline than using some
sort of embedded policy model. 

The format of the input and output from Portcullis to and from the PDP is standardized. There may be some different wrapping
needed for different PDPs, but the guts should remain the same.  

## Escalation
the trickiest concept in Portcullis is probably escalation. We have chosen to use JWTs to represent the data that tells
the PDP that a particular request is 'blessed' by the user (or the organzation).  JWTs provide several benefits: expiration,
various signing strategies, well-supported.  The `portcullis` claim in the JWT is a JSON object that represents details
about a request (or a set of very closely related requests) that would normally be forbidden, but are temporarily allowed.

### Escalation examples
It's probably fine for the agent to use an MCP to read from certain project directories on your computer.  Probably not fine for the
agent to read from most other directories. For example, you may not normally want
your agent to be reading from `/var/log` on a server.  But sometimes it might be the right thing. So you can create a JWT that
includes a `portcullis` claim that elaborates on the set of MCP services, tools and arguments that are approved.

## Sample Policy
The Rego samples are an effort to think through some of the common use cases. The goal here is to give you a set of 
patterns that you can use to implement the policy that your organization needs.  We wrote the Rego policies in two
different styles, for the implementor's benefit.




