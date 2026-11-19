# FAQ and Common Objections

## Frequently Asked Questions

**Will this work with our existing IdP (Okta / Azure AD / Ping)?**

Yes. Gate sends an OIDC token to Keep, and Keep validates and parses it. As long as it follows the JWT model and Keep can reach the public key for signature validation, it should work fine.

**What happens if the PDP is unavailable?**

Portcullis fails closed, returning an error to the agent and user. Keep never forwards an MCP request to a backend unless the PDP responds with `allow`.

**Can an agent exfiltrate data through an authorized tool?**

Yes. Portcullis governs access to tools, not the security of the tools themselves.

**What happens if Gate is unavailable?**

The agent will not be able to access any MCPs protected by Portcullis. This is typically resolved by restarting Gate. Gate reports its own degraded state via the `portcullis_status` tool so users know what failed.

**What happens if Keep is unavailable?**

You won't be able to use any MCPs protected by Keep. Setting up Keep in a high-availability cluster is recommended.

**What happens if Guard is unavailable?**

Agents can still use MCPs for work that policy allows outright, but there is no escalation path until Guard recovers.

**Do my MCP tool authors need to know about Portcullis?**

No. Portcullis is transparent to MCP tool implementations. The tools do not change.

**Does Gate store the user's OIDC token anywhere?**

You have options. Gate can pull the token from storage, or use an OIDC login flow to fetch credentials from the IdP and keep them in memory only. In multi-tenant mode, the agent receives an HMAC-based token for its session.

**If a blackhat user gets access to the OIDC token, can they abuse it?**

It depends on the token type. DPoP or mTLS-bound tokens are much less vulnerable than plain bearer tokens. Mitigations include using OIDC login (no token on disk), requiring escalation for high-privilege calls, and placing Guard behind an SSO proxy.

**Is the policy managed by groups, roles, user IDs, or something else?**

Keep pulls claims from the OIDC token and sends them as part of the Principal to the policy engine. You control the policy, so you can enforce on any claim or combination of claims.

**My users have several agents on their desktop — how does this work?**

The stdio interface means each agent gets its own Gate instance. Gate also supports a streamable-HTTP mode so one Gate instance can serve multiple agents in parallel, both in single-tenant and multi-tenant mode.

**Can I test my policies before deploying them?**

Yes. For OPA:

- OPA control plane systems such as [EnforceAuth.com](https://enforceauth.com) support multiple environments and code promotion.
- The open-source Raygun testing tool can exercise policy bundles against known inputs.
- `opa test` lets you test policies directly with unit tests.

**How do I change my policies?**

Manage the policy like any other codebase, build OPA bundles, and deploy them. Keep watches for bundle updates automatically. [PAC.Labs](https://paclabs.io) has extensive experience helping organizations adopt Policy-as-Code with OPA.

**How do I rotate secrets?**

Restart Keep, Guard, and multi-tenant Gate instances to pick up new secrets. In a cluster, a rolling restart avoids downtime. Single-tenant Gate restarts frequently anyway, tied to the user and agent session.

**How do I update my tools without restarting the whole system?**

Use the `POST /admin/reload` endpoint on Keep (see [configuration.md](configuration.md)). A rolling restart is also an option for zero-downtime upgrades.

**Does Portcullis support Resources and Prompts, or just Tools?**

Currently Portcullis is focused on Tools, as they represent the highest security risk. As a workaround for data access, expose sensitive data via read-only Tools so they can be governed by the same policy engine. Resources and Prompts are under consideration for the roadmap.

**Can Portcullis run in an air-gapped or offline environment?**

Yes. Portcullis has no external dependencies by default. Use a local OPA instance, a local Redis for caching, and an internal OIDC provider (Keycloak, Dex, etc.). No data leaves your network unless you explicitly configure a remote SIEM or webhook sink.

**What about telemetry and monitoring?**

OpenTelemetry is embedded in all three components. Keep, Guard, and multi-tenant Gate expose `/metrics` (Prometheus scrape), `/healthz`, and `/readyz`.

For audit logging, there are two complementary mechanisms:

- **OPA decision log** — records every policy decision (allow/deny/escalate) with structured metadata, configurable via standard OPA decision log plugins.
- **Keep MCP Activity Log** — records every MCP request, policy decision, and tool response payload passing through Keep. Supports a rotating local file sink, an HTTP batch sink (Splunk HEC, custom ingest), and an OTLP sink. See [configuration.md](configuration.md) for details.

**What happens if a user approves an escalation by mistake? Can it be revoked?**

Every escalation token has a mandatory TTL. Users can also visit the Gate management page (default: `http://localhost:7777`) to see active escalation tokens and revoke them immediately.

**What is the difference between an Escalation Token and an OIDC Token?**

The OIDC token proves who you are (Alice). The escalation token proves what Alice told the agent it could do (`DROP TABLE 'X'`). Both are required for sensitive actions: the OIDC token provides identity context, and the escalation token provides the specific human-verified override for a policy boundary.

**What is the most secure Portcullis setup?**

- Gate uses interactive OIDC login (Authorization Code + PKCE)
- Gate stores the short-lived OIDC token in memory only
- Keep validates issuer, audience, and expiry and enforces short TTL
- Gate-to-Keep uses mTLS
- High-privilege actions require escalation by policy
- Guard is behind a corporate SSO proxy to prevent direct agent approval

**Auditors want to know that Portcullis is capturing everything.**

Keep's MCP Activity Log records every request and response payload passing through it, including the PDP decision for each call. OPA's decision log provides a parallel, policy-engine-level record of every evaluation. The only current gap is Gate's local filesystem fast-path — reads and writes handled there do not pass through Keep and therefore do not appear in the Keep activity log. That gap is on the roadmap.

**Will this solution run well in a multi-region enterprise?**

Yes. The per-call workload is moderate, and the dominant latency in the workflow is the AI model's response time. Multiple regional Keep/Guard clusters can run in isolation; the Gate config determines which regional cluster it connects to. Different departments or business units with different IdPs or certificate requirements can each have their own Gate/Keep/Guard family.

**How do I know the human actually reviewed the arguments in the Guard UI?**

The decision logs capture a complete audit trail: the original request, the escalate decision, and the subsequent allow decision including the JTI of the escalation token. The JTI can be cross-referenced with Guard logs to show which user approved which arguments, at what time, and from which IP address.

---

## Common Objections

**Keep is a single point of failure.**

Keep holds minimal in-memory state. Redis-backed caching and clustered deployments offer high availability and scalability.

**I don't have managed devices, so this won't work.**

You can still enforce policy on any MCP tool that is managed by the organization. Put core enterprise MCP tools behind a firewall accessible only by Keep. Unmanaged-device users calling external MCPs would not have access to organization resources through those MCPs anyway.

**Agents can spoof the requests.**

Agent MCP requests are wrapped in metadata that includes the verified user identity, and the channel is protected by bearer tokens. An agent would need to make raw HTTP POST requests, know Keep's location, hold the user's OIDC token, and know the bearer token — a much higher bar than a passthrough connection.

**Escalation is not secure.**

Escalation is optional and fully controlled by policy — you can disable it entirely. For deployments that use escalation, Guard should be placed behind a corporate SSO proxy (Cloudflare Access, Pomerium, nginx + oauth2-proxy) so only a human who can satisfy an interactive SSO challenge can reach the approval page. An agent that receives the approval URL cannot complete an SSO login. See [guard-sso-proxy.md](guard-sso-proxy.md).

**Great, another policy language.**

Portcullis does not implement a policy engine — it integrates with existing ones. The reference implementation uses OPA and Rego. Any PDP that can respond with structured allow/deny/escalate decisions can be plugged in.

**This won't scale to the size of my organization.**

Keep and the PDP scale horizontally. You can have geographically disparate Keep clusters with regional Gate instances configured to talk to the nearest Keep and Guard clusters.

**Guard maintains user state, so it can't scale.**

Guard uses Redis for distributed escalation state and can be deployed as a cluster. Keep also uses Redis for multi-tenant escalation token storage, with context-partitioned keys that keep each user's state isolated.

**I can't have MCP servers in my network.**

Keep does not care where MCP backends are located. The backends could be external, with Portcullis as the single internal egress point that the firewall permits to reach them.

**I don't want to write custom policy for every tool.**

The reference implementation includes a table-based policy lookup model that covers common cases without custom Rego. It also supports delegation to custom Rego logic when you need it.

**We would need helpdesk support to implement this.**

[PAC.Labs](https://paclabs.io) provides implementation services and several tiers of support, including 24/7 if required.

**We would need mTLS between servers.**

Gate-to-Keep mTLS is supported. Gate-to-Guard mTLS is on the roadmap.

**This will add latency to MCP calls.**

Yes, like any system that enforces fine-grained policy. The added latency is on the order of 10–100 ms, against AI response times measured in seconds.

**I already have MCPs deployed and don't want to move them yet.**

You are not required to put all MCPs behind Portcullis. You can migrate tools into the Portcullis security framework gradually, at your own pace.

**Policies will get complex.**

A complex-but-correct policy is better than a simple-but-wrong one. The table-based policy model handles common cases simply. [PAC.Labs](https://paclabs.io) can help with policy architecture and authoring.

**My JWT claims are non-standard.**

Keep supports a webhook to normalize JWT claims into a canonical Principal. The normalized Principal can be cached in Redis to reduce I/O.

**We already have an API gateway. Why do we need Portcullis?**

Standard API gateways see a single `POST /call` with a JSON body — they do not understand MCP. Portcullis understands the intent inside the MCP request: which tool is being called and what the specific arguments are (e.g., which table is being dropped). A traditional gateway is a drawbridge; Portcullis provides guards who inspect everything that passes through.

**AI agents are non-deterministic. If I approve a DROP TABLE today, how do I know the agent won't hallucinate a DROP TABLE tomorrow using the same token?**

Escalation tokens are cryptographically bound to the specific arguments of the request. An approval for `DROP TABLE temp_logs` generates a JWT that only authorizes that exact command. An attempt to call `DROP TABLE users` with the same token will be denied. Portcullis turns probabilistic AI behavior into deterministic security outcomes.

**What stops a user from bypassing Gate and connecting their agent directly to the backend MCP servers?**

In production, backend MCP servers can be configured to accept connections only from Keep (via mTLS or firewall rules). By locking the back door, Portcullis becomes the only path to enterprise tools.

**This will slow down my users' experience.**

Portcullis adds 10–100 ms per call. AI model response times are measured in seconds. The overhead is imperceptible.

---

## Acknowledgements

1. This project would not exist without Open Policy Agent and Rego.
2. XACML provided early inspiration for thinking about policy tests as structured data.
3. IronCurtain inspired thinking about how to scale that concept to an enterprise level.
4. Mark Rogge of EnforceAuth produced a diagram that included the concept of an MCP proxy, which was the seed of this architecture.
5. Thanks to Patrick, Dylan, Sunny, and Ed for patience and support throughout development.
