# Phase 2

## Tasks


### Task: Improve API
- We need to version Keep's API with Gate, or version the Wrapped MCP Request, or both, so we know what to expect in the contents
- We need to version the logging API (how Gate sends logs to Keep)
- priority: high , but only after we've gotten all of the core communications done, no need in versioning our API too early





### Task: Improve Secret Management
- We probably need to support a way to gather secrets (Private keys, shared secrets) from a vault, but don't get rid of the config option for the sandbox model
- priority: medium


  Execution Plan: Pluggable Secret Management

  1. Implement a simple "Fetch-Only" Resolver in internal/shared/secrets.
    - Use Scheme Handlers:
       * envvar:// -> Just calls os.LookupEnv. (5 lines of code)
       * filevar:// -> Just calls os.ReadFile. (5 lines of code)
       * vault:// -> Use the official HashiCorp Vault client (which we were going to use anyway).
    - The Escape Hatch: We design our SecretResolver interface so that if we ever truly need the full Go CDK power later, we can
      simply swap the implementation without changing the Keep or Guard code.


  2. Recommendation: Write a Surgical "URI Parser"
    Since the official hashicorp library doesn't support URIs, and we want to keep the "Lite" model, the most robust way is to use Go's standard
    net/url package to parse the string ourselves and then call the official SDK.

    - General Format
      vault://[mount]/[path]#[key]

      * vault://: The mandatory scheme identifying the resolver.
      * [mount]: The name of the Secret Engine (e.g., secret, kv, production).
      * [path]: The logical path to the secret.
      * #[key]: The specific field name inside the secret's JSON payload.

    - Example of how we'd implement it:

```go
    uri := "vault://secret/data/keep#mykey"
   
    u, _ := url.Parse(uri)
   
    // 1. Get the Mount (The Host)
    mount := u.Host // Result: "secret"
   
    // 2. Get the Path and strip the leading slash
    fullPath := strings.TrimPrefix(u.Path, "/") // Result: "data/keep"
   
    // 3. Extract everything after "data/" for KV v2
    // We use strings.TrimPrefix to handle the specific KV v2 requirement
    secretPath := strings.TrimPrefix(fullPath, "data/") // Result: "keep"
   
    key := u.Fragment   // result:  mykey
    // Then use the official SDK:
    secret, _ := client.KVv2(mount).Get(ctx, secretPath)
    value := secret.Data[key]
```
    The full implementation will also handle parse errors, empty mounts, empty fragments (defaults to 'value')

    Why this is the right move:
    * Control: You aren't fighting a library's specific URI implementation.
    * Official Stability: You use the official HashiCorp SDK for the actual network call, ensuring maximum security and feature
      support (like TLS and namespaces).
    * Clean YAML: Your users get the "Anchor Pattern" they expect from other modern tools.

      The Portcullis Secret URI Specification
      - can be found in README.md



  3. Update Server Constructors
    We will update the NewServer functions in Keep and Guard to resolve their critical secrets during initialization:
    * Keep Server: Resolves EscalationRequestSigning.Key and Auth.BearerToken.
    * Guard Server: Resolves EscalationTokenSigning.Key, Keep.PendingEscalationRequestSigningKey, and Auth.BearerToken.
    * Context: Since secret resolution is an I/O operation, I'll ensure these constructors handle a context.Context (or use a
      startup-scoped context) for timeouts.
    * This will affect 30+ constructors including test cases, but it is the right thing to do, better now than later

  4. Configuration File Processing
    Configuration file processing must now be performed in a specific order:
    - parse YAML
    - resolve secrets
    - validate resolved values (length/format) according to already-specified validation criteria that do not need to be revisited here

  5. Remove ${ENV_VAR} pattern from all yaml files and replace with envvar://ENV_VAR as appropriate 
    - there is exceptionally low migration risk in this repo state

  6. Testing
  - I'll add a unit test in internal/shared/secrets/resolver_test.go to verify that 
    `filevar://` and `envvar://` resolution works as expected.
  - Verify that the ${ENV_VAR} pattern is no longer supported
  - Other tests required:
    - missing variable/file cases
    - unsupported scheme behavior
    - timeout/cancellation behavior
    - constructor integration tests in Keep and Guard
    - assurance that secret values never appear in error strings/log output
   

#### Important Refactoring
1. Server constructors are currently context-free. Introducing context-aware secret resolution affects all call sites and tests. 
2. We will need examples of using the the anchor pattern with `vault://path#key` so administrators will know how to include their
   hashicorp vault configurations.
   - examples are included in the README.md

#### Specified Behaviors

- Is the intended behavior startup-only resolution, or hot reload/rotation support?
  - Pulling secrets from vaults is a one-time operation at startup.  The Portcullis servers (Keep, Gate and Guard) will need
    to restart to fetch new secrets

- Which exact URI schemes are in scope for first release, and which are examples only?

  - These schemes will be fully implemented and verified with unit tests.

      1. no scheme: The legacy behavior. Raw strings are accepted as-is for local sandbox development.
      2. envvar://: Resolves secrets from environment variables (e.g., envvar://SIGNING_KEY). This is safer than plaintext YAML and works in
          standard Docker environments.
      3. filevar://: Resolves secrets from local files (e.g., filevar:///etc/portcullis/signing.key). This allows enterprises to use
          Kubernetes "Secret" mounts or existing configuration management tools.
      4. vault://: The primary enterprise target. We will implement the native Vault Shim (using VAULT_ADDR and VAULT_TOKEN) to support
          HashiCorp Vault.

  - Deferred (Phase 2 / Later)
    These require importing heavy cloud-provider SDKs (AWS/GCP/Azure) and setting up complex test environments. By deferring them, we
    keep the PR surgical and the binary size lean for the first release.

    1. awssec://: AWS Secrets Manager.
    2. gcpsec://: GCP Secret Manager.
    3. azkv://: Azure Key Vault.

- Do you want fail-closed startup (recommended) when any required secret cannot be resolved?
  - the servers (Keep/Guard) should fail-closed at startup
  - Gate should run in degraded mode, which is already a defined failure mode for Gate. It does not stop running, because that
    would make it impossible for the user to determine what the problem is, it would just appear that Portcullis wasn't responding
    without any feedback. It is better for Gate to remain operational and return error messages to the user and Agent when the
    agent tries to use the MCPs

- Should secret references be allowed in all config fields or only an allowlist?

   - I recommend restricting vault-style secret resolution to fields that actually hold cryptographic 
     material or authentication credentials.  So currently: `vault://` and in the future `awssec://`, `gcpsec://` and `azkv://` can only be
     used for the hardcoded allowlist of fields.  
      - note:  `filevar://` and `envvar://` can be used anywhere

      Keep Server
      * escalation_request_signing.key (HMAC/RSA Key)
      * listen.auth.bearer_token (API Auth)
      * admin.token (Admin API Auth)

      Guard Server
      * escalation_token_signing.key (HMAC/RSA Key)
      * keep.pending_escalation_request_signing_key (Public Key for verification)
      * auth.bearer_token (API Auth)

      Gate (Future)
      * management_api.shared_secret

    - future secrets that would be filled via `vault://` or similar mechanisms will have to be added to the allowlist

    - Recommendation
      We should implement the Resolve call explicitly in the constructors (NewServer) for these specific fields. This keeps the
      configuration loading phase (LoadConfig) fast and deterministic, while the initialization phase handles the "heavy lifting" of
      secret resolution for the Allowlist.
      - this list of allowed fields will be hard-coded


  2. Every secret-bearing configuration field must be wired up to this, not just the major ones
     - the list of fields that will be supported is listed above



#### Vault Support

  1. Vault Configuration (The "Meta-Secret" Problem)
  To avoid the "Where does the Vault token come from?" chicken-and-egg problem, we will follow the Twelve-Factor App best practice:
  Infrastructure Configuration via Environment.
   * Vault Config: We will use the official github.com/hashicorp/vault/api client, which automatically respects standard environment
     variables: VAULT_ADDR, VAULT_TOKEN, VAULT_NAMESPACE, and VAULT_CACERT.
   * Why this works: In a production enterprise environment (Kubernetes/Cloud), these variables are injected by a Vault Agent
     sidecar or a Kubernetes Mutating Webhook. Portcullis doesn't need to "know" about the Vault infrastructure; it simply expects
     the standard environment to be present.


  Why this addresses your concerns:
   * Implementation Risk: We've identified that vault:// requires a custom implementation (the shim) rather than a non-existent Go
     CDK driver.
   * Configuration: We've defined that Vault infrastructure details (VAULT_ADDR, etc.) are handled via standard environment
     variables, keeping the keep.yaml focused only on the secret's location.
   * Consistency: The operator sees a unified URI-based experience regardless of whether the backend is File, Environment, or Vault.
   * Future Ready: In the future, when we wish to implement AWS, Azure and GCP secrets, we will have the patterns in place to support them.



  Why this is the "Enterprise" way:
  This design means that in a production keep.yaml, a security team can simply point to a vault path
  (vault://secret/data/portcullis/keep#signing_key), and the application will never see the raw secret on disk or in its environment
  variables.





### Task: Input sanitizing at Keep and Guard
- standard good hygiene
- medium priority



### Task: add http for gate, so it can support multiple agents in parallel
i.e. instead of running as a stdio MCP, it can run as an autonomous local process.
- Portcullis-Gate needs to be concurrency-safe
- priority: medium-low





### Task: Routing model for Workflows
when the PDP generates a 'workflow' response, the important information should be
sent to the appropriate workflow system to allow for authorization. But it is quite possible
that in a large organization, different workflow systems will be used to authorize
different types of requests - for example, by MCP, or even perhaps by Tool.

We need to modify the Keep config to allow different workflow plugins to be invoked
for different service / tool combos 

- priority: low





### Task: Acquire Human Credentials (at Gate)
- [x] Token file (Option B) — Gate reads `identity.oidc.token_file`; fails hard (no OS fallback) when source is "oidc" and token is missing or invalid; `~` is now expanded correctly on read
- [ ] Keychain storage — optional future enhancement
- [ ] Device authorization grant (RFC 8628) — fallback for when no token file exists; deferred until enterprise adoption confirmed (see Implementation Details below)
- priority: low


### Task: Fail closed for Gate if Keep is unavailable
- this is not super important, since if Keep is down, no non-local MCP requests can occur
- Basically, ensure that Gate indicates to the user that the Portcullis server is not available right now, try again later.
- low priority


### Task: Optionally Include the traceid in the Deny, Escalate and Workflow messages back to the user
- purpose: allows a user to escalate to the enterprise security team if they aren't allowed to do something they think they should be able to
- low priority



### Task: Optionally create a Gate API to collect the list of DENY responses, along with trace/session information
- not sure if this is necessary. It might be helpful for troubleshooting
- very low priority



## Security Review


1. High: Guard token-claim surface is capability-based and can be open depending on config
- Claim endpoint intentionally unauthenticated: server.go:139
- Guard can run with no bearer token protection for token APIs: server.go:385
- Unclaimed-list response includes raw token material: server.go:414
  
Why this is major:
- Security posture depends heavily on deployment hardening.
- In permissive deployments, token retrieval paths expose high-value artifacts.

Suggested direction:
- Require auth by default for token APIs, return only metadata from list endpoints, and keep raw token retrieval tightly scoped/authenticated.









# Phase 3 / Future

### Task: Pluggable Logging and Redaction
- **Problem**: Enterprises need flexible logging destinations (SIEMs, files, console) and must ensure that sensitive PII or secrets in tool arguments are never leaked to those logs.
- **Fix**: Implement a `LogSink` interface and a "Fail-Safe" redaction engine.
- **Fail-Safe Redaction Definition**: If the redaction engine encounters an error (recursion limit, malformed data), it must replace the entire payload with an error message rather than logging raw data.
- **Implementation scope**:
  - `internal/keep/logsink.go` — Define the `LogSink` interface (`Write`, `Close`).
  - `internal/keep/redaction.go` — Implement the redaction engine with support for:
    - **Global Deny-List**: Keys like `password`, `token`, `secret` are always redacted.
    - **Tool-Specific Rules**: Specific arguments for specific tools (e.g., `email` in `update_user`).
    - **Strict Mode**: An optional "safe-by-default" mode where only explicitly allowed keys are logged.
  - `internal/keep/decisionlog.go` — Refactor to support multiple sinks and apply redaction before sending.
  - **New Sinks**: Implement `ConsoleSink`, `FileSink`, and refactor the existing `WebhookSink`.
- priority: medium


## Implementation notes


  




