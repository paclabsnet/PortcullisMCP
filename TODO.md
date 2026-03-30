# Feature:  Secure Authorization Flow




0. Gate: create a new identity source for the config yaml, called: "oidc-login" . change the existing oidc source to
   "oidc-file"
1. Gate: Authorization Code + PKCE login flow using a standard OIDC config. localhost callback listener, short-lived
   one-time session, CSRF-safe
         - Keep the resulting `oidc-token` and `refresh-token` in memory
2. Gate: automatically refresh the `oidc-token` as required
3. Gate: return the login url (perhaps: http://localhost:7777/auth/login) to the Agent as a response to an Agent, when
   the token is not in-memory.
4. Gate: modify startup logic so that Gate sends the login URL to the Agent when necessary, and doesn't go into degraded
   mode
5. Keep: configurable max TTL enforcement on inbound OIDC tokens.
6. Gate: We'll need a post-callback HTML page. Probably should be embedded by default, with an optional config override.
7. Gate: we need an additional pseudo-MCP tool, called: `portcullis_login` . It is a local tool that will provide the
   Agent and user with the URL for the login page to start the oidc login process.

## Architecture

We're going to change Gate to be a state machine with the following states:
  - unauthenticated
  - authenticating (the user has been given a login url and are somewhere in the login flow)
  - authenticated (the user has logged in, and Gate has received the appropriate token)
  - system-error, which will have the following sub-states:
    - refresh-failed (We tried to refresh a token and it did not work, perhaps a network error, or a revoked token)
    - invalid (e.g. a config file problem, or a network problem (unable to talk to Keep, etc), or a bad token, or any
      other failure)

Gate starts up in `unauthenticated`, regardless of source.

Gate reads and validates the config file. If there is any problem validating the config file, Gate transitions to:
`system-error`:`invalid` . A `system_error_summary` string and `system_error_detail` string will be created, describing
the issue that put us into this state.

Based on source, different things will happen:

source: "os"
  - we perform whatever setup work we need, and immediately move to the `authenticated` state
  - When we we are in the `authenticated` state
     - when we received the `portcullis_login` tool request, we respond with "Login is not necessary."
     - when we receive any other MCP request from the Agent, we process it normally.
     - If there is an error while interacting with Keep or Guard, we move to the `system-error`:`invalid` state (and
       substate)


source: "oidc-file"
  - we read in the oidc-token from the file. If it doesn't exist or is invalid, we immediately move to the
    `system-error`:`invalid` state (and substate)
    - otherwise, we move immediately to the `authenticated` state
  - When we we are in the `authenticated` state
     - when we received the `portcullis_login` tool request, we respond with "Login is not necessary."
     - when we receive any other MCP request from the Agent, we process it normally.
     - If there is an error while interacting with Keep or Guard, we move to the `system-error`:`invalid` state (and
       substate)


source: "oidc-login"
  - we wait for the Agent to interact with us with an MCP request.
  - if we are in the `unauthenticated` state, we act as if the user requested the `portcullis_login` tool, and invoke
    that tool.
     - one of the side effects of `portcullis_login` is to put us in the `authenticating` state.
  - If we are in the `authenticating` state, and the user uses an MCP, we respond with something like: "please complete
    the login process. Use the `portcullis_login` tool to start over"
     - if we successfully receive an oidc-token at the callback address, we move to the `authenticated` state
     - if we fail to receive an oidc-token in an appropriate time, we move to the state: `system-error`:`invalid`
  - When we transition to the `authenticated` state
     - we set up an asynchronous refresh cycle to update the token as required. If there is already an asynchronous
       refresh cycle, we cancel it and create a new one.
       - if the token refresh fails for any non-natural expiration reason, we move to the
         `system-error`:`refresh-failed` state (and substate).
       - when the refresh-token expires naturally, we move to the `unauthenticated` state
     - after that, we should refresh the list of MCP tools from Portcullis-Keep
  - When we we are in the `authenticated` state
     - when we receive an MCP request from the Agent, we process it normally.
     - If there is an error while interacting with Keep or Guard, we move to the `system-error`:`invalid` state (and
       substate)
  - when we are in the `system-error` state (and *any* substate)
     - if the user requests the `portcullis_status` tool, we return that information
     - if the user requests the `portcullis_login` tool, we invoke that tool
     - any other MCP tool: we respond with text, pulled from the config YAML, something like: "Portcullis-Gate is having
       trouble. Use `portcullis_status` tool for more details, or use `portcullis_login` to reset the system
       and log in again."



**portcullis_login tool**

The behavior of this tool varies based on the identity source:

- os:  respond with "Login is not necessary"
- oidc_file: respond with "Login is not necessary"
- oidc_login:
   - if the state is NOT `authenticated`
    - set the state to `authenticating`
    - provide a message (pulled from config YAML) that will contain the login url, to the Agent (and thus the user) to
      allow them to start the login process again
   - if the state is `authenticated`
     - respond with a message to the Agent (and thus the user) indicating that the user is already successfully logged
       in


**portcullis_status tool**
Basically the same as it currently behaves, except that it uses the state `system-error` as the indicator that there's a
problem, rather than `degraded mode`




## Docker Changes

We need to add an IdP provider container that we can use as a IdP for oidc-login . It will need to be configured with
reasonable defaults and secrets, and those secrets
will need to be mirrored in the gate oidc example YAML.

Claude suggests `dex` : https://github.com/dexidp/dex

  - the Dex realm/config file that needs to be committed alongside docker-compose.yml.
  - Dex is configured via a single YAML file
    - deploy/docker-sandbox/dex-config.yaml (or similar) needs to be created as part of that work, pre-configured with a
      static user and a client matching the gate example YAML.
    - a static password connector config in Dex is sufficient for testing


## Portcullis-Gate YAML changes

oidc-login config will look something like:

```yaml
identity:
  oidc_login:
    issuer_url: "https://login.example.com"   # for OIDC discovery
    redirect_uri: ""   # if blank, use the default: http://localhost:{port}/auth/callback  , if not blank, use whatever is given.
    client_id: "portcullis-gate"
    client_secret: "envvar://GATE_CLIENT_SECRET"  # optional for public clients
    scopes: ["openid", "profile", "email", "groups"]
    flow: "authorization_code"  # other options reserved for future implementation
```

- we will need a configuration YAML field `login_callback_timeout_seconds` with a sensible default
- we will need a configuration YAML field: `login_callback_page_file`: ""  # default: embedded



## Notes

-  We do not have to worry about backwards compatibility.

- PKCE state parameter storage: The auth code callback needs to validate the state
  parameter against what was sent in the authorization request (CSRF protection).
  This needs a short-lived in-memory store keyed by state value — a map with
  expiry cleanup.
    - A nonce must be generated per-login, included in the authorization request, and verified against the nonce claim
      in the returned ID token.

- Validation:
  - Management API must be enabled for oidc-login: If management_api.port is 0 (disabled), there's no HTTP server to
    receive the
    /auth/callback redirect. Config.Validate() should reject `identity.source`: `oidc-login` when the management API is
    disabled, with a
    clear error.
  - `client_secret` in SecretAllowlist: Gate's SecretAllowlist in config.go controls which fields can use `vault://` and
    similar
    resolvers. `identity.oidc_login.client_secret` needs to be added to it, otherwise vault-backed client secrets won't
    work.
  - "authorization_code" is the only valid option for `flow`

- If the IdP sends back an error=access_denied or error=invalid_request to the callback, we move to the state:
  `system-error`:`invalid`,

- when the refresh-token expires, Gate needs to move back to the `unauthenticated` state

- refresh cycle timing: We recommend: refresh at expiry - max(60s, lifetime * 0.1)

