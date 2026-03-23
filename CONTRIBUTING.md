# Contributing to PortcullisMCP

Thank you for your interest in contributing.

## Getting Started

1. Fork the repository and create a branch from `main`.
2. Make your changes. Run `make test` to verify all tests pass.
3. Submit a pull request with a clear description of what you changed and why.

## Development Setup

```sh
# Build all binaries
make build

# Run tests
make test

# Start the demo stack (requires Docker)
make demo-start
```

See `config/` for example configurations and `demo/` for the Docker-based sandbox.

## Guidelines

- Keep changes focused. One concern per pull request.
- Add tests for new behaviour. Bug fixes should include a test that would have caught the issue.
- Do not introduce global state. Dependencies are injected at startup.
- All functions that do I/O take `context.Context` as their first argument.
- Errors are returned, not panicked.
- Configuration is via YAML. Secrets are referenced via `${ENV_VAR}` expansion, never hardcoded.

## Security Issues

Do not open a public issue for security vulnerabilities. See [SECURITY.md](SECURITY.md) for the responsible disclosure process.

## License

By contributing, you agree that your contributions will be licensed under the Apache License 2.0.
