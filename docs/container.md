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
credentials into the image. Production configuration and the distinction
between static and HTTP policy backends are defined in
[configuration.md](configuration.md). In summary, a secure environment must
use HTTPS endpoints, Hydra admin authentication, `STATE_STORE=redis`,
`rediss://` Redis with a non-empty environment-specific prefix, and either
static subject-scope rules or a configured authenticated HTTP policy backend.
The in-memory store is intended only for local development and tests.

The server listens on `:8080` by default. `/healthz` is used by the image
healthcheck and reports process liveness. Use `/readyz` for an orchestrator
readiness probe. It checks Hydra and Kratos readiness and also checks Redis or
Valkey when `STATE_STORE=redis`; it does not call the HTTP policy endpoint.

The release workflow publishes the image to GHCR after scanning both platform
digests and attaching SBOM, provenance, and keyless Cosign signature metadata.
Deployments must use a verified digest rather than a moving tag. See the
[image release and verification guide](release.md) and the
[deployment image contract](deployment.md#image-supply-chain).
