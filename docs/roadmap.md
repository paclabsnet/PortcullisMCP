# Phase 3

Some of these tasks were deferred from Phase 2 because they are complicated and involve access to potentially expensive
cloud resources


### Task: Support 'escalate' in multi-tenant environments
Providing a way for a user of an AI-enabled console to escalate privileges for an AI Agent is tricky, and we need time to figure out how to explain the approval process to the user.


### Task: Gate should keep track of 'unused' escalation approval URLs for a time
When Gate receives an `escalate` response and passes that on to the Agent, there's no guarantee that the Agent will provide the link to the user.  We can include the link in the Gate management UI.  If the user creates the appropriate escalation-token, that's evidence that we can remove the link from the management UI.




### Task: Support vault:// secret resolution for map[string]string config fields

The secret resolver walks named struct fields via dot-notation and resolves secret
URIs (`vault://`, `envvar://`, etc.) in string values. It does not currently traverse
`map[string]string` values, so fields like `decision_logs.headers` and
`webhook.headers` cannot use vault:// or envvar:// for individual header values
(e.g. `Authorization: "envvar://SIEM_TOKEN"`).

The example configs document this limitation with a note directing operators to
populate these fields from external secrets tooling before startup.

The fix is to extend the resolver to walk map values and apply secret resolution
to each entry, subject to the same allowlist rules. Both Keep's
`decision_logs.headers` and `webhook.headers` (and any future map-valued fields)
would benefit.

- priority: medium-low






### Task: Support Cloud Vaults
These require importing heavy cloud-provider SDKs (AWS/GCP/Azure) and setting up complex test environments. By deferring
them, we
keep the scope of the first release a little more manageable

1. awssec://: AWS Secrets Manager.
2. gcpsec://: GCP Secret Manager.
3. azkv://: Azure Key Vault.

- priority: low
- comment: this is potentially expensive to implement, and it make sense to wait until we actually see someone using
  this solution




### Task: Routing model for Portcullis-Keep and Workflows
when the PDP generates a 'workflow' response, the important information should be
sent to the appropriate workflow system to allow for authorization. But it is quite possible
that in a large organization, different workflow systems will be used to authorize
different types of requests - for example, by MCP, or even perhaps by Tool.

We need to modify the Keep config to allow different workflow plugins to be invoked
for different service / tool combos

- priority: low
- comment: this is probably interesting, but we don't have any enterprise-scale 
  workflow tools to use for testing purposes, which makes this challenging to design, difficult to implement and impossible to test




### Task: Acquire Human Credentials (at Portcullis-Gate)
- [x] OIDC login - Gate (via the Agent) sends the user to a login page and accepts the oidc-token as a callback
  after a successful login.
- [x] Token file — Gate reads `identity.oidc.token_file`; fails hard (no OS fallback)
  when source is "oidc" and token is missing or invalid; `~` is now expanded
  correctly on read
- [ ] Keychain storage — optional future  source of identity
- [ ] Certificate - optional future source of identity
- [ ] Device authorization grant (RFC 8628) — probably not necessary
- priority: low
- comment: different organizations have different ways of providing identity. Would 
  prefer to wait for feedback before trying to implement specific additional identity sources



### Task: add streamable-http access for Portcullis-Gate, so it can support multiple agents in parallel
i.e. instead of running as a stdio MCP, it can run as an autonomous local process.
- IMPORTANT! Portcullis-Gate would need to be concurrency-safe
- priority: medium
- comment: it makes sense to wait until we see organizations encountering this issue 
  and preferring a standalone streaming-http solution over a set of stdio solutions listening on different ports


### Task: Optionally create a Portcullis-Gate API to collect the list of DENY responses, along with trace/session information
not sure if this is necessary. It might be helpful for troubleshooting
- priority: very low
- comment: not sure if the juice is worth the squeeze


### Task: Add a login capability to Portcullis-Guard
This would potentially prevent a particularly nasty rogue agent from knowingly creating a request that would require
escalation, waiting for the response, abusing some sort of direct HTTP mechanism to edit and approve the request, and
then trying again, without the user being aware that it was happening.
- priority: medium-low
- comment: much of this is just a port of the equivalent work we've done for 
  Portcullis-Gate login


### Task: Allow the 'edit' capability for escalation claims to be turned on and off by configuration
This should be straightforward - the edit capability is already on a templated web page, so it should
be easy enough to remove the edit option via template rules
- priority: medium

### Task: Consider some mechanism to explain the escalation claims in human language
This might be very tricky, given how complex some MCP requests can be.
- priority: low

### Task: Configuration option to disable the Portcullis-Gate web page, thus eliminating port contention
- priority: medium-low
- comment: without the web interface, Portcullis-Gate can't offer oidc-login
- comment: if we offer the streamable-http version, there won't generally be port 
  contention 

### Task: Potential for limited-use of the escalation tokens at Portcullis-Gate
Configuration option at Portculils-Gate to allow escalation tokens to be used a limited number of times before being
automatically deleted
- priority: low
- comment: this might be a feature for auditors? Not sure


### Task: Add performance monitoring to Portcullis-Keep
Use the OpenTelemetry wrapper around HTTP calls to get detailed performance measurements
- priority: medium







### Task: Improve policy messaging for denials
Right now, the denial reason is fairly generic. But in the Rego reference implementation, we could include a reason as
part of the response,
potentially customized to each rule, which could then be echoed to the user.
- priority: low








### Task: consider renaming 'requires_approval' to 'escalation' in gate config Agent messaging
This is a config consistency issue - Gate has configuration that lets IT customize
the messages delivered to the User for escalation and deny results.  But instead of
calling it `escalate`, we're calling it `requires_approval`.  Which is simultaneously
more informative and less consistent.
- priority: low








### Task: Add a security posture assessment at startup
log the full resolved security posture at startup regardless of mode — every security-relevant property, its value, and whether it meets production standards. Vault does this well. That log becomes an artifact that feeds directly into audit evidence without requiring auditors to understand your config schema.
- priority: medium-low



### Task: Migrate all the security complaint supression (in dev mode)
The default behavior in dev mode is to generate a warning message when there
is a security violation.  Then we've added a few 'supression' flags to keep
the system from generating a particular warning.  All of these flags should
be moved to be "under" the `mode: dev` flag, so the developers who don't need
to see the flags can turn them on and off easily.  
- priority: low
- comment: this is mostly a feature of convenience




-----------------------------------------------------
# Phase 4

### Task: Allow Portcullis-Keep to add extra data to MCP server calls
if the MCP server requires a secret or some sort of certificate in order to accept MCP requests, Keep can be
modified
- priority: medium-low
- comment: this could be really tricky to implement properly, need a lot of examples first



-----------------------------------------------------

# Phase 99

These tasks seem unnecessarily complex and not worth doing

### Task: Reload Secrets at Keep and Guard
Full config reload via admin API — extend Keep's `POST /admin/reload` and add an
equivalent Guard endpoint to re-resolve all secrets (including `vault://` URIs)
without a process restart, enabling zero-downtime secret rotation
- priority: medium-low




-----------------------------------------------------
# Completed Tasks


### Task:  Add a logging-level command-line flag to Keep, Gate and Guard (DONE)
So we can turn on debugging and info level logs as appropriate.  Also add log-level to
the YAML configuration.  Command line flag overrides YAML.
- comment: if the mode is production, and the command-line mode is set, emit a warning message that the command line setting (X) has overridden the setting in
the config (Y)
- priority: medium-low




### Task: Add an 'any' arg_restriction to the Rego reference implementation  (DONE)
Functionally `{"type":"any", "key_path":"customer_id"}` is equivalent to
`{"type":"prefix","key_path":"customer_id","data":""}` but the `any` tag
is a little more clear that this will match any argument supplied.  Also,
the `any` type works better for non-string arguments
- priority: medium-low
- comment: in practice, this is basically 'enable' for the MCP tool . Akin to what `permit.io` is offering




### Task: Add preferred_username and acr claims to Principal (DONE)

Two common OIDC claims are not currently extracted by the `oidc-verify` normalizer:

- `preferred_username` — In Azure AD and many enterprise IdPs, `sub` is a pairwise
  opaque per-application identifier, not the UPN. The human-readable, policy-writable
  login name is `preferred_username`. OPA rules written against `alice@corp.com` need
  this field, not `sub`.

- `acr` (Authentication Context Class Reference) — A string describing the
  authentication strength achieved, e.g. `"urn:mace:incommon:iap:silver"` or `"mfa"`.
  Complements the existing `amr` (methods used) by giving policies a single level
  signal: "deny privileged tools unless acr indicates MFA".

Changes required: add `PreferredUsername string` and `ACR string` fields to both
`shared.UserIdentity` and `shared.Principal`; extract them in
`keep/identity.go:oidcVerifyingNormalizer.Normalize`; pass them through in
`passthroughNormalizer.Normalize`; update the Rego reference implementation to
expose both fields to policies.

- priority: medium



### Task: Allow multiple sandbox directories in Gate config (DONE)

Currently `sandbox.directory` accepts a single path. Users with multiple unrelated
working trees (e.g. `~/projects/client-a`, `~/projects/client-b`, `/var/data/exports`)
have no clean way to fast-path all of them without opening up a broad common ancestor.

Change `sandbox.directory` (string) to `sandbox.directories` (list of strings), keeping
`sandbox.directory` as a backward-compatible alias for a single entry. All listed
directories are equally trusted for fast-path; protected paths continue to take
precedence over all of them. No per-directory policy — keep it simple.

Affected code: `gate/config.go`, `gate/fastpath.go`, `gate/localfs/server.go`
(`NewServer` takes `[]string`), and the `list_allowed_directories` tool response.

- priority: medium



### Task: Add distributed caching to the Portcullis-Guard (DONE)
- [x] Redis token store — pending escalation requests and unclaimed tokens can be stored in Redis
  (`token_store.backend: "redis"`), enabling shared state across multiple Guard instances and
  survival across Guard restarts.  Sandbox docker-compose includes a Redis 7 container.
- priority: high



### Task: Enrich the capabilities of portcullis-localfs policy (DONE)
Allow IT to configure the policy to allow for local writes, deletes, et al, to certain directory trees without checking
agains Portcullis-Keep
- priority: low


### Task: Allow a managed-device signal (device cert, workload identity, or attestation) in addition to user token (DONE)
Keep should be configured to validate the additional proof-of-identity information.
Policy should require both: trusted user identity and trusted device posture for privileged tool usage.
- priority: low



### Task: Add mTLS support for Gate to Guard (DONE)
So every path is protected in the same way that the Gate to Keep path is protected. Ideally we re-use the certs we created for Gate, create new certs for Guard and set up
the config for Guard in a way that is consistent with the mTLS config for Keep. Then 
write some tests to make sure it works.

- priority: medium



### Task: mTLS test coverage for Gate-Keep transport (DONE)

Add test coverage for the mTLS authentication path between Gate and Keep.

**Docker sandbox certs** — generate a self-signed CA, a Keep server cert, and a Gate client cert
(all with 10-year expiry) and commit them under `docker/tls/` as test fixtures. Update
`docker/keep-demo.yaml` and `docker/gate-config.yaml` (or equivalent) to mount and reference
these certs so the full Docker Compose demo stack exercises real mTLS end-to-end.

**Go unit tests** — add an in-memory test helper (using `crypto/x509` + `crypto/tls`) that
generates a CA + server cert + client cert at test time. Use it to cover:
- Keep server: rejects connections with no client cert
- Keep server: rejects connections with a client cert signed by an untrusted CA
- Keep server: accepts connections with a valid client cert signed by the configured `client_ca`
- Gate client: `server_ca` is used to verify Keep's certificate
- Gate client: connection fails when Keep presents a cert signed by an untrusted CA

These two approaches complement each other: the Docker certs prove the real file-based config
works end-to-end; the in-memory tests cover edge cases quickly without file dependencies.

- priority: medium
- comment: the Gate-side mTLS client setup already has basic validation tests in `forwarder_test.go`;
  the Keep-side server setup and end-to-end handshake are the gaps




------------------------------------------------

