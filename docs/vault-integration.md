# Vault Secret URI Configuration

## General Format

```
vault://[mount]/[path]#[key]
```

- `vault://` — the mandatory scheme identifying the resolver
- `[mount]` — the name of the Secret Engine (e.g., `secret`, `kv`, `production`)
- `[path]` — the logical path to the secret
- `#[key]` — the specific field name inside the secret's JSON payload

## Examples (Vault KV v2)

If your secret is at path `portcullis/signing` in the default `secret/` mount:

```yaml
key: "vault://secret/portcullis/signing#key_value"
```

Resolution:
1. Fetch from Vault: `secret/data/portcullis/signing` (the `data/` prefix is automatically inserted by the SDK for KV
   v2)
2. Extract field: `key_value`

### Multiple keys from the same path

```yaml
user: "vault://secret/db#username"
pass: "vault://secret/db#password"
```

### No anchor

If the anchor is omitted (e.g., `vault://secret/my-secret`), Portcullis looks for a default key named `value`. If that
key does not exist, it returns an error.

### URL encoding

If your path contains `#` or `?`, URL-encode them (e.g., `%23`).

## Administrative Prerequisites

The resolver expects the standard Vault environment variables to be set on the host:

| Variable | Required | Description |
|---|---|---|
| `VAULT_ADDR` | Yes | URL of the Vault server |
| `VAULT_TOKEN` | Yes | Authentication token (or managed via Vault Agent) |
| `VAULT_NAMESPACE` | No | Vault Enterprise namespace |
