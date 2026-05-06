# Portcullis System Requirements

This document lists the minimum versions of all third-party tools and services
required to build, run, or deploy Portcullis.

---

## Build Requirements

| Tool | Minimum Version | Notes |
|------|----------------|-------|
| Go | 1.24 | Required by the MCP go-sdk |
| Make | any | Standard on Linux/macOS; `winget install ezwinports.make` on Windows |

---

## Runtime: Core Components

These are required whenever Portcullis is deployed.

| Component | Minimum Version | Notes |
|-----------|----------------|-------|
| Redis | 6.2 | Required for `GETDEL` (atomic single-use state tokens). Used for session storage, escalation state, and backend OAuth flow state. |

---

## Runtime: Policy Enforcement

Required when using OPA as the PDP backend (the default for non-trivial deployments).

| Component | Minimum Version | Notes |
|-----------|----------------|-------|
| OPA | 0.50 | Bundle support required. Tested against the `openpolicyagent/opa:latest` image. |

---

## Runtime: Identity / OIDC

Required when using OIDC-based user authentication. Dex is the reference identity
provider used in the demo stack; any RFC 8414-compliant OIDC provider is supported.

| Component | Minimum Version | Notes |
|-----------|----------------|-------|
| Dex | 2.35 | Reference OIDC provider used in the demo stack. |

---

## Runtime: Container / Orchestration

Required when using the provided Docker Compose demo stack or building container images.

| Component | Minimum Version | Notes |
|-----------|----------------|-------|
| Docker Engine | 20.10 | Earlier versions lack multi-stage build features used in the Dockerfile. |
| Docker Compose | v2.0 (Compose V2) | The `docker compose` plugin syntax is used throughout. The legacy `docker-compose` v1 binary is not supported. |

---

## Notes

- The **noop PDP** mode requires only Go and (optionally) Redis. OPA is not needed.
- The **minimal single-tenant setup** (no Docker, no OPA) requires only Go and Make.
  See the Quick Start in the README.
- **MCP backends** (e.g. EnforceAuth, custom enterprise APIs) have their own
  requirements defined by their providers and are not listed here.
