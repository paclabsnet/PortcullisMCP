# Phase 2

## Tasks





### Task: Security Review


High: Unsafe default identity trust model for OIDC claims
Files: identity.go:73, identity.go:34, keep-config.example.yaml:28
Impact: strict mode forwards OIDC-sourced claims without cryptographic verification; if Keep is reachable by a malicious caller with valid transport access, this can enable claim injection into authorization decisions.
Fix: make oidc-verify the production default, or make strict strip unverified OIDC claims too.

High: JWKS URL trust not constrained to HTTPS
Files: identity.go:51, identity.go:78
Impact: accepting non-TLS JWKS endpoints can allow key substitution/MITM in hostile network conditions.
Fix: require https for jwks_url by default; add explicit dev override only if needed.

High: JWKS retrieval path lacks timeout/context-bound request
Files: identity.go:354, identity.go:336
Impact: auth path can hang on slow/unresponsive JWKS servers, causing degraded or stalled request handling.
Fix: use http client with explicit timeout + NewRequestWithContext and bounded retry behavior.

Medium: Documented/configured backend type mismatch (SSE)
Files: config.go:149, router.go:342, README.md:199
Impact: configuration/docs imply sse support, runtime rejects unsupported backend type; integration confusion/failures for external users.
Fix: either implement sse in router or remove sse from docs/comments and examples.

Medium: Outbound HTTP clients missing explicit timeouts in several paths
Files: forwarder.go:48, guardclient.go:41, router.go:349
Impact: dependency stalls can increase tail latency and tie up resources during partial outages.
Fix: set standard client/transport timeouts (dial/TLS/headers/total), keep context deadlines too.

Medium: Decision logs include raw tool arguments without redaction controls
Files: server.go:307, server.go:337, server.go:240, decisionlog.go:183
Impact: secrets/PII passed in tool arguments may be exported to SIEM/console.
Fix: add configurable redaction policy (default masking for common sensitive keys).

Low: Gate management API can run unauthenticated on localhost by default
Files: api.go:35, api.go:75, gate-config.example.yaml:29
Impact: local process/user on same host can call token/identity management endpoints if shared_secret is unset.
Fix: require shared secret by default or emit strong startup warning when disabled.

Low: Fast-path decision logs can be dropped under pressure with limited observability
Files: server.go:310, server.go:340
Impact: possible silent audit gaps during spikes.
Fix: expose dropped-log counters/metrics and periodic warnings.









------------------------------------------------------------------------------------


# Phase 3 / Future

Some of these tasks were deferred from Phase 2 because they are complicated and involve access to potentially expensive cloud resources

Some of these tasks are 


### Task: Support Cloud Vaults (Phase 3)
    These require importing heavy cloud-provider SDKs (AWS/GCP/Azure) and setting up complex test environments. By deferring them, we
    keep the scope of the first release a little more manageable

    1. awssec://: AWS Secrets Manager.
    2. gcpsec://: GCP Secret Manager.
    3. azkv://: Azure Key Vault.

    - priority: low
    - comment: this is potentially expensive to implement, and it make sense to wait until we actually see someone using this solution



### Task: Routing model for Workflows
when the PDP generates a 'workflow' response, the important information should be
sent to the appropriate workflow system to allow for authorization. But it is quite possible
that in a large organization, different workflow systems will be used to authorize
different types of requests - for example, by MCP, or even perhaps by Tool.

We need to modify the Keep config to allow different workflow plugins to be invoked
for different service / tool combos 

- priority: low
- comment: this is probably interesting, but we don't have any enterprise-scale workflow tools to use for testing purposes, which makes this
           challenging to design, difficult to implement and impossible to test




### Task: Acquire Human Credentials (at Gate)
- [x] Token file (Option B) — Gate reads `identity.oidc.token_file`; fails hard (no OS fallback) when source is "oidc" and token is missing or invalid; `~` is now expanded correctly on read
- [ ] Keychain storage — optional future  source of identity
- [ ] Certificate - optional future source of identity
- [ ] Device authorization grant (RFC 8628) — probably not necessary
- priority: low
- comment: different organizations have different ways of providing identity. Would prefer to wait for feedback before trying to implement specific additional identity sources



### Task: add streamable-http access for Gate, so it can support multiple agents in parallel
i.e. instead of running as a stdio MCP, it can run as an autonomous local process.
- IMPORTANT! Portcullis-Gate would need to be concurrency-safe
- priority: low
- comment: it makes sense to wait until we see organizations encountering this issue and preferring a standalone streaming-http solution over a set of stdio solutions listening on different ports


### Task: Optionally create a Gate API to collect the list of DENY responses, along with trace/session information
not sure if this is necessary. It might be helpful for troubleshooting
- priority: very low
- comment: not sure if the juice is worth the squeeze




## Implementation notes


  
