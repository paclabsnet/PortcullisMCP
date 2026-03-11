# policy tests

These are just examples of how to implement the AI agent policy.  Portcullis-Keep
sends the MCP arguments to a PDP, which could be OPA or could be something else.

In this case, we implemented the policy in OPA because it's a well-established policy language and it lines up
well with the expertise of PACLabs . 

But you don't have to use OPA, and you don't have to use the policy framework we've created. 

## Using OPA

If you do want to use OPA, these tests use the open source tool 'raygun' https://github.com/paclabsnet/raygun
to validate the behavior of the policy logic

There are two different implementations of the policy, for the benefit of the reader.

One uses custom rego rules

The other uses a table-driven data element, which does a fair amount of the grunt
work for you, but will probably not scale to the most complex scenarios.

The raygun tests are using the 'tabular' policy path (so using the table-driven policy
found in data.json, in the directory above this one). The exact same (in theory) logic
has been implemented in the 'custom' policy path.  You can create the equivalent raygun
tests using the `convert.sh` script, which does a simple sed, replacing tabular with custom

## Writing your own policy

The data-driven policy table is probably an easy place to get started. You don't have to
just use the policy table, you can add custom rules to the tabular decision.rego (or
more modularly, call out to custom policy in a different package) .

## Creating your own escalation tokens

For simplicity, and to demonstrate the concept, I just implemented shared-secret JWTs. There's
no reason that the JWTs couldn't use PK signatures, it's just a hassle for me to get that set up
for a PoC.


