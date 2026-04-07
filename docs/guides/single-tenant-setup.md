# Single Tenant Portcullis Guide

The single-tenant infrastructure is:
- Centralized Portcullis-Keep
- Centralized Portcullis-Guard
- Local Portcullis-Gate

Here's how I exercise the system using this model:

0. acquire the portcullis-gate executable
    - this will be included in the release, but you can also do `make build` on the command line

1. execute `make demo-start` to run the docker-singletenant sandbox  (deploy/docker-singletenant)

    This will set up a workable Portcullis-Keep and Portcullis-Guard, with a bunch of additional support components, including:
    - Open Policy Agent (pre-configured with some basic rules)
    - Dex IdP (to demonstrate oidc-login capability)
    - Redis (to demonstrate how to set up for high availability)
    - 2 MCPs
        - fetch (works, actually fetches URLS from remote servers)
        - mock-enterprise-api (read-only eye candy)

2.  move the portcullis-gate executable to a directory where Claude desktop (or any other desktop that supports MCPs) can find it
  - `deploy/docker-singletenant/gate-demo.yaml` provides a functional starting point for configuring portcullis-gate to run . 
  - You will need to add Portcullis as an MCP. Typically this means that the portcullis-gate binary is on your PATH, and then you give the MCP the command line, such as:  `"-config", "~/.portcullis/gate.yaml"`   (note that the YAML file can be almost anywhere, it doesn't have to be in a `.portcullis` directory in your home directory, that's just for convenience)


3. Start up your Agent.  It should launch the Portcullis MCP automatically

4. You can ask your Agent what tools are available.  Portcullis automatically includes 
   - `portcullis_login` - for logging into an oidc provider. This only applies if Gate is configured for login
   - `portcullis_status` - this will return a status report about the portcullis system, with hints for how to troubleshoot if something has gone wrong
   - `portcullis_refresh` - sometimes, the list of tools will be incomplete at startup, this is a way to refresh the list

Once you're logged in (or immediately if login isn't required), Portcullis-Gate will fetch the list of tools supported by Keep. That is your list of tools


5. Do stuff

Assuming you have logged in, or bypassed login, you should now be able to interact with Portcullis and the MCPs behind it.

One simple example:

`> get customer 312`  *sometimes "use portcullis to get customer 312*

`> query orders for customer 312`

`> set the status of order ABC-123 to 'SHIPPED'`

That last one should trigger an escalation, where you'll be invited to click a link which opens up Portcullis-Guard.  Guard will then allow you to approve the escalated authority. If you do so, you can repeat the previous command and it should immediately work.




