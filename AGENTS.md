# Repository Guide

## Project Shape

- Go module: `github.com/kroderdev/hydra-kratos-login-consent` (`go 1.26`).
- Runtime entrypoint and composition root: `cmd/server/main.go`.
- Core dependencies point inward: `internal/core/{domain,ports,application,config}`.
- `internal/adapters/inbound/http` is the browser-facing HTTP adapter.
- `internal/adapters/outbound/{hydra,kratos,policy,state}` implement driven ports.
- `internal/config` only loads environment variables into the core configuration.
- Use manual constructor injection; do not add a service container or globals.
- Keep Docker and Kubernetes concerns at the deployment boundary, outside the core.

## Security Boundaries

- Hydra owns OAuth2/OIDC protocol state and tokens; Kratos owns identities,
  sessions, authentication methods, and MFA.
- Never store or expose passwords, TOTP secrets, provider secrets, Hydra admin
  credentials, cookies, tokens, or login/consent challenges.
- Treat the external UI as untrusted. Revalidate Hydra challenges, clients,
  redirect URIs, scopes, transaction handles, Kratos sessions, AAL, and policy
  decisions server-side.
- Preserve exact allowlists, secure headers, request limits, upstream timeouts,
  graceful shutdown, `/healthz`, and `/readyz` behavior.

## State And Configuration

- Configuration is environment-based; see `README.md` for the supported variables.
- `STATE_STORE` supports `memory` for local development/tests and `redis` for
  secure or shared deployments; secure environments reject `memory`.
- The in-memory transaction store is for local development and tests, not replica
  deployments. Shared Redis/Valkey state is required for release deployment.
- Do not put customer-specific authorization rules in the generic core; implement
  them behind the policy port.

## Commands

Use the Makefile where possible:

```text
make fmt       # gofmt -w .
make test      # go test -shuffle=on ./...
make race      # go test -race -shuffle=on ./...
make vet       # go vet ./...
make lint      # golangci-lint run ./...
make security  # govulncheck ./...
make check     # fmt, test, race, vet, lint; does not run security
```

For focused work, use `go test ./path/to/package` or
`go test -run TestName ./path/to/package`.

Required validation order before reporting a change complete:
`gofmt -w .`, `go test ./...`, `go test -race ./...`, `go vet ./...`,
`golangci-lint run ./...`, `govulncheck ./...`.

## Go Workflow

- Co-locate tests with the package under test; keep adapter and application tests
  independent of live Hydra, Kratos, or Redis services unless explicitly marked
  as integration tests.
- Preserve dependency direction: core packages must not import concrete adapters,
  HTTP handlers, environment loading, or storage implementations.
- Update `docs/` when flow behavior, trust boundaries, configuration, or
  deployment assumptions change.
- For Go tasks, read `.agents/skills/golang-how-to/SKILL.md` first and load the
  relevant repository-local Go skills.
