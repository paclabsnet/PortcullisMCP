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

  1. Add Dependencies
  I will add gocloud.dev to the project's go.mod file to enable the URI-based secret resolution drivers.

  2. Create internal/shared/secrets/resolver.go
  I'll implement a Resolve function that handles the URI logic:
   * Direct Mode: If the string has no ://, it's returned as-is (backward compatibility).
   * URI Mode: If it has a CDK-supported scheme (e.g., filevar://, envvar://), it uses runtimevar.OpenVariable to fetch the value.
     if it uses `vault://` it will use the custom shim
   * Schemes: I'll include support for filevar:// and envvar:// (built into Go CDK) immediately.

  3. Update Server Constructors
  I will update the NewServer functions in Keep and Guard to resolve their critical secrets during initialization:
   * Keep Server: Resolves EscalationRequestSigning.Key and Auth.BearerToken.
   * Guard Server: Resolves EscalationTokenSigning.Key, Keep.EscalationRequestSigningKey, and Auth.BearerToken.
   * Context: Since secret resolution is an I/O operation, I'll ensure these constructors handle a context.Context (or use a
     startup-scoped context) for timeouts.

  4. Configuration File Processing
    Configuration file processing must now be performed in a specific order:
    - parse config file
    - resolve secrets
    - validate resolved values (length/format) according to already-specified validation criteria that do not need to be revisited here

  5. Remove ${ENV_VAR} pattern from all yaml files and replace with envvar://ENV_VAR as appropriate 
    - there is exceptionally low migration risk in this repo state

  6. Testing
  - I'll add a unit test in internal/shared/secrets/resolver_test.go to verify that filevar:// and envvar:// resolution works as
    expected.
  - Verify that the ${ENV_VAR} pattern is no longer supported
  - Other tests required:
    - missing variable/file cases
    - unsupported scheme behavior
    - timeout/cancellation behavior
    - constructor integration tests in Keep and Guard
    - assurance that secret values never appear in error strings/log output
   

#### Important Refactoring
1. Server constructors are currently context-free. Introducing context-aware secret resolution affects all call sites and tests. 


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
  - Gate should run in degraded mode, which is already a defined failure mode for Gate

- Should secret references be allowed in all config fields or only an allowlist?

   - I recommend restricting secret resolution to fields that actually hold cryptographic material or authentication credentials:

      Keep Server
      * escalation_request_signing.key (HMAC/RSA Key)
      * listen.auth.bearer_token (API Auth)
      * admin.token (Admin API Auth)

      Guard Server
      * escalation_token_signing.key (HMAC/RSA Key)
      * keep.escalation_request_signing_key (Public Key for verification)
      * auth.bearer_token (API Auth)

      Gate (Future)
      * management_api.shared_secret

    - Recommendation
      We should implement the Resolve call explicitly in the constructors (NewServer) for these specific fields. This keeps the
      configuration loading phase (LoadConfig) fast and deterministic, while the initialization phase handles the "heavy lifting" of
      secret resolution for the Allowlist.
      - this list of allowed fields will be hard-coded


  2. Every secret-bearing configuration field must be wired up to this, not just the major ones
     - the list of fields that will be supported is listed above



#### Vault Support

  Refined Design: Hybrid Resolution Strategy

  The core issue is that while gocloud.dev/runtimevar is excellent for cloud-native providers (AWS/GCP), it does not have a built-in
  driver for fetching secret strings from HashiCorp Vault. To address this without increasing risk, we will use a Hybrid Resolver.

  1. Explicit Driver Registration
  In internal/shared/secrets/resolver.go, we will explicitly import and register the Go CDK drivers. This ensures that the registry
  is populated and "Fail-Fast" behavior is enforced at startup.

```go
    import (
        _ "gocloud.dev/runtimevar/filevar"
        _ "gocloud.dev/runtimevar/envvar"
        _ "gocloud.dev/runtimevar/constantvar"
    )
```

  2. Vault Configuration (The "Meta-Secret" Problem)
  To avoid the "Where does the Vault token come from?" chicken-and-egg problem, we will follow the Twelve-Factor App best practice:
  Infrastructure Configuration via Environment.
   * Vault Config: We will use the official github.com/hashicorp/vault/api client, which automatically respects standard environment
     variables: VAULT_ADDR, VAULT_TOKEN, VAULT_NAMESPACE, and VAULT_CACERT.
   * Why this works: In a production enterprise environment (Kubernetes/Cloud), these variables are injected by a Vault Agent
     sidecar or a Kubernetes Mutating Webhook. Portcullis doesn't need to "know" about the Vault infrastructure; it simply expects
     the standard environment to be present.

  3. The vault:// Shim
  Since there is no Go CDK driver for Vault strings, we will implement a surgical "Shim" in our resolver:
   * Scheme: vault://<path/to/secret>#<key>
   * Logic:
       1. Initialize a vault.NewClient (using standard env).
       2. Read the secret at <path/to/secret>.
       3. Extract the value for <key>.

  4. Updated Resolution Logic

```go
    func Resolve(ctx context.Context, uri string) (string, error) {
        if !strings.Contains(uri, "://") {
            return uri, nil // Direct mode
        }
        u, err := url.Parse(uri)
        if err != nil { return "", err }
        switch u.Scheme {
        case "vault":
            return resolveVault(ctx, u) // Handled by our native Vault shim
        default:
            return resolveGoCDK(ctx, uri) // Handled by Go CDK (File, Env - future: AWS, GCP, etc)
        }
    }
```

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


  




