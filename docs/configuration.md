# Configuration Reference

Configuration for all three Portcullis components. For system requirements, see [system-requirements.md](system-requirements.md).

## Gate (`~/.portcullis/gate.yaml`)

Gate is not started manually. Configure your MCP client to launch it via stdio:

```json
"mcpServers": {
    "portcullis": {
        "command": "portcullis-gate",
        "args": ["-config", "~/.portcullis/gate.yaml"]
    }
}
```

Example configs in `config/`:

| File | Purpose |
|------|---------|
| `gate-config.minimal.yaml` | Minimal config for local testing (no OIDC) |
| `gate-config.minimal-oidc-login.yaml` | Minimal config with OIDC login |
| `gate-config.example.yaml` | Full production config with mTLS |

Verify Gate is running via the management API at `http://localhost:7777`. You can also use the `portcullis_status` MCP tool inside your agent to check system health.

### Identity override (local testing)

When using the OS identity source, you can override user identity fields to simulate different users and group memberships without real OIDC infrastructure:

```yaml
identity:
  strategy: "os"
  user_id: "alice@example.com"
  display_name: "Alice Developer"
  groups:
    - "developers"
    - "admin"
```

If `user_id` is not specified, it defaults to the OS username. OS identity is for testing only; production deployments should use OIDC.

For the difference between single-tenant and multi-tenant Gate, see [single-vs-multi-tenant-portcullis-gate.md](single-vs-multi-tenant-portcullis-gate.md).

### Gate degraded mode

Gate does not shut down on configuration errors or network failures. Instead, it enters Degraded Mode:

- The `portcullis_status` MCP tool (always available) returns a description of the current error — misconfiguration, network access problems, incorrect keys, etc.
- This allows users to report the specific problem to IT support without needing to know what failed internally.

## Keep

Example configs in `config/`:

| File | Purpose |
|------|---------|
| `keep-config.minimal.yaml` | Uses `noop` PDP (allows all); no OPA required |
| `keep-config.example.yaml` | Full production config with mTLS and OPA |

```sh
# Run Keep with the minimal config (noop PDP, development only)
make run-keep
```

### Redis (Keep)

Keep uses Redis for multi-tenant escalation state (pending escalation store and issued escalation token store). Redis 6.2+ is required for the `GETDEL` command used for atomic single-use token retrieval. See [system-requirements.md](system-requirements.md).

### Escalation scoping (multi-tenant)

In multi-tenant mode, Keep's `escalation` config key controls how escalation state is partitioned across users:

```yaml
escalation: "session"       # scope pending state to the user's session (default)
# escalation: "fingerprint" # scope to a stable fingerprint of the user's identity
# escalation: "disabled"    # disable escalation entirely
```

### MCP Activity Log

Keep logs every MCP request, policy decision, and tool response to a configurable sink. This is independent of OPA's decision log and captures the full request and response payloads.

```yaml
mcp_activity_log:
  enabled: true
  file: "/var/log/portcullis/activity.log"   # lumberjack rotating file sink
  max_size_mb: 100
  max_backups: 5
  max_age_days: 30
  include_pdp_decision: true    # include the full PDP response in each log entry
  truncate_payloads: true        # truncate large payloads to a configured maximum
  buffer_size: 1000              # async buffer depth
```

**Remote sinks** are also supported for zero-disk or SIEM-forwarding deployments:

- **HTTP batch sink** — posts log entries as `ndjson` or `json_array` to any HTTP endpoint (Splunk HEC, custom ingest, etc.)
- **OTLP sink** — sends log entries as OpenTelemetry log records to any OTLP-compatible backend

PDP errors always produce a log entry with `pdp_decision: "error"` regardless of the `include_pdp_decision` setting.

### Admin reload

Keep exposes `POST /admin/reload`, which re-reads `keep.yaml` from disk and reconnects to all configured backends. Useful for adding or removing MCP backends without a full restart. Protected by an `X-Api-Key` header matching the `admin.token` value in config.

## Guard

Example configs in `config/`:

| File | Purpose |
|------|---------|
| `guard-config.minimal.yaml` | Minimal config for local testing |
| `guard-config.example.yaml` | Full production config |

For production Guard deployments, Guard should be placed behind a corporate SSO proxy (Cloudflare Access, Pomerium, nginx + oauth2-proxy, etc.) to prevent agent self-approval. See [guard-sso-proxy.md](guard-sso-proxy.md).

## Demo stack configs

Located in `deploy/docker-singletenant/`:

| File | Purpose |
|------|---------|
| `keep-demo.yaml` | Keep config for the Docker demo stack |
| `guard-demo.yaml` | Guard config for the Docker demo stack |
| `opa-config.yaml` | OPA config for the Docker demo stack |

## Environment variables

All configs support `envvar://` syntax for secret injection. Use this instead of hardcoding values:

```yaml
backends:
  github:
    type: "stdio"
    command: "npx"
    args: ["-y", "@modelcontextprotocol/server-github"]
    env:
      GITHUB_TOKEN: "envvar://GITHUB_TOKEN"
```

## External secret sources

Configs also support `filevar://` and `vault://` for reading secrets from files or HashiCorp Vault:

```yaml
# Read from a file
some_secret: "filevar:///run/secrets/my_secret"

# Read from Vault
some_secret: "vault://secret/data/portcullis#my_key"
```

See [vault-integration.md](vault-integration.md) for the full URI specification, examples, and administrative prerequisites.

## Policy

The included sample policy in `policies/` provides a working starting point:

- Allows filesystem reads within the sandbox
- Requires escalation for writes to certain directories
- Denies access to protected paths (`.git`, `.portcullis`)
- Allows some mock enterprise API tools, denies or escalates others based on group membership
- Allows some websites via fetch, denies or escalates others

See [policy/opa-examples.md](policy/opa-examples.md) for detailed policy examples and testing guidance.

## mTLS

Gate-to-Keep mTLS is supported. See [guides/mtls-setup.md](guides/mtls-setup.md) for certificate setup. Gate-to-Guard mTLS is on the roadmap.

## OpenTelemetry

OpenTelemetry is embedded in all three components. Keep, Guard, and multi-tenant Gate expose `/metrics` (Prometheus) and standard `/healthz` / `/readyz` endpoints. Single-tenant Gate supports `/healthz` and `/readyz` via its management API.
