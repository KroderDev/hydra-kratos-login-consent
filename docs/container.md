# Container Deployment

The repository Dockerfile builds and tests a static Linux server binary in
separate build stages, then copies it into a minimal Alpine runtime image. The
runtime process runs as the non-root `app` user and includes only the binary,
CA certificates, and the utilities required for the Docker healthcheck.

Build the image from the repository root:

```sh
docker build --tag hydra-kratos-login-consent:local .
```

Supply configuration and secrets at runtime. Do not copy `.env` files or
credentials into the image. A production deployment must use HTTPS endpoints,
Hydra admin authentication, `ENVIRONMENT=production`, `STATE_STORE=redis`,
`rediss://` Redis with a non-empty environment-specific prefix, and explicit
`ALLOWED_SUBJECT_SCOPES`; the in-memory store is intended only for local
development and tests.

The server listens on `:8080` by default. `/healthz` is used by the image
healthcheck and reports process health. Use `/readyz` for an orchestrator
readiness probe because it verifies the configured Hydra, Kratos, and state
store dependencies.
