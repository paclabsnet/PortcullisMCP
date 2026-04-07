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

4. You can ask your Agent what tools are available.  Portcullis includes 
