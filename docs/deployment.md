# Deployment

This document is the authoritative production runtime contract. It is
platform-neutral: a container orchestrator, virtual machine service, or other
runtime may implement it. Kubernetes is shown only as one example.

## Required Boundaries

Production deployments must satisfy all of the following:

- Use `ENVIRONMENT=production` or another secure environment value.
- Serve every browser-facing URL over HTTPS. Configure `PUBLIC_URL` and
  `EXTERNAL_UI_URL` with `https://` URLs.
- Use HTTPS for server-to-server HTTP URLs: `HYDRA_ADMIN_URL`,
  `HYDRA_PUBLIC_URL`, `KRATOS_PUBLIC_URL`, and `POLICY_URL` when HTTP policy is
  selected.
- Use `STATE_STORE=redis` with a shared Redis or Valkey service and a
  `rediss://` `REDIS_URL`.
- Keep `HYDRA_ADMIN_URL` and Hydra admin endpoints private. The provider must
  be the only component that can use Hydra admin credentials.
- Keep Kratos administrative endpoints private. The provider uses the Kratos
  public session API for `whoami` and readiness; expose only the Kratos browser
  API surface that the external UI intentionally needs.
- Route only the provider's documented browser endpoints to the public edge. Do
  not expose a generic Hydra or Kratos proxy.
- Supply `HYDRA_ADMIN_TOKEN`, and the HTTP policy token when applicable, through
  a runtime secret mechanism.
- Configure exact client, redirect URI, scope, audience, and claim allowlists.

The server listens for plain HTTP on `LISTEN_ADDR` (default `:8080`); it does
not load TLS certificates itself. A deployment must provide a TLS-capable
front door or sidecar and protect the hop to the process according to its
network security policy. `PUBLIC_URL` being HTTPS enables secure browser
cookies and HSTS; it is not a substitute for securing the network path.

## Browser Transaction Flow

The OAuth client and Hydra own the OAuth protocol. This service owns the
server-side handoff between Hydra and the external Kratos UI:

1. Hydra redirects the browser to `/login`, `/consent`, or `/logout` with an
   opaque challenge.
2. The provider retrieves the challenge through its private Hydra admin API and
   validates the client, redirect URI, scopes, audiences, and relevant policy
   inputs against its configuration.
3. The provider creates a short-lived, single-use transaction in Redis/Valkey,
   binds it to a provider-issued HttpOnly browser-state cookie, and redirects
   the browser to the configured external UI. For an HTTPS provider URL, that
   cookie is also `Secure` and `SameSite=None`; local HTTP development uses
   `SameSite=Lax`.
4. The UI receives only `flow`, an opaque `transaction`, an opaque `csrf`, and a
   fixed `return_to` callback. Consent also receives safe display data such as
   `client_name`, `scope`, and an optional `skip_consent` hint. The Hydra
   challenge and all admin credentials stay server-side.
5. The external UI runs the Kratos browser flow and returns the browser to the
   provider. Login completes with `GET /login/callback`; consent submits a form
   to `POST /consent`; logout submits a form to `POST /logout`.
6. The provider revalidates the transaction, CSRF value, browser-state cookie,
   Kratos session, assurance level, allowlists, and policy decision. It then
   accepts or rejects the original Hydra challenge through the private admin
   API and redirects the browser to Hydra's validated result.

The external UI is untrusted. It must not provide a subject, AAL, AMR, policy
decision, claims, or token values for the provider to accept. The browser must
retain the Kratos session credential needed by the provider's callback; cookie
domain, SameSite, and cross-origin behavior must be configured for the chosen
UI and Kratos topology. State-changing consent and logout requests must include
an `Origin` exactly matching the configured external UI origin.

The transaction handle and CSRF value are opaque credentials. Do not put them
in analytics, referrer logs, screenshots, or support tickets.

## Shared State And Replicas

Redis/Valkey is not an optional cache for production. It is the shared store for
browser transaction records and replay protection:

- Use one reachable shared service for all provider replicas.
- Use `rediss://` and normal certificate verification in secure environments.
- Set a non-empty, environment-specific `REDIS_KEY_PREFIX`.
- Ensure the store's availability and capacity match the deployment's failure
  and traffic requirements.
- Do not run multiple replicas with `STATE_STORE=memory`.

The provider stores only short-lived transaction state. Hydra remains the owner
of OAuth protocol state and tokens, and Kratos remains the owner of identities,
sessions, authentication methods, and MFA.

## Endpoints And Probes

The provider exposes these routes:

| Method | Path | Deployment use |
|---|---|---|
| `GET` | `/login` | Hydra login handoff |
| `GET` | `/login/callback` | External UI login completion |
| `GET` | `/consent` | Hydra consent handoff |
| `POST` | `/consent` | External UI consent completion |
| `GET` | `/logout` | Hydra logout handoff |
| `POST` | `/logout` | External UI logout completion |
| `GET` | `/healthz` | Process liveness |
| `GET` | `/readyz` | Dependency readiness |

`GET /healthz` returns `200` with `{"status":"ok"}` when the process can
serve the request. It does not call Hydra, Kratos, Redis/Valkey, or the policy
service.

`GET /readyz` returns `200` with `{"status":"ready"}` only when the configured
Hydra admin readiness endpoint and Kratos readiness endpoint respond
successfully. With `STATE_STORE=redis`, it also requires a successful Redis
`PING`. The in-memory store has no external readiness check. The HTTP policy
endpoint is not called by `/readyz`; policy errors during a login or consent
flow fail closed. When possible, the provider rejects the Hydra challenge with
the safe `temporarily_unavailable` outcome rather than exposing policy details.

Use `/healthz` for liveness and `/readyz` for readiness. Do not use liveness to
remove a healthy process merely because an upstream dependency is unavailable.
Do not expose either probe publicly unless the deployment requires it.

## Secrets And Logging

Inject secrets at process startup using the runtime's secret facility or an
equivalent protected environment mechanism. Do not bake `.env` files or secret
values into an image or deployment artifact. Do not expose Hydra admin or policy
credentials to the external UI, browser, or client application.

Application and edge logs must redact or exclude:

- `Authorization` headers and bearer credentials.
- `HYDRA_ADMIN_TOKEN`, `POLICY_AUTH_TOKEN`, and Redis credentials.
- Kratos session cookies and provider browser-state cookies.
- Hydra login, consent, and logout challenges.
- Transaction handles and CSRF values.
- Request query strings or form fields that contain the values above.

The provider's access log records request ID, method, route, status, and
duration, not query or form values. Operators must apply the same rule to
reverse-proxy, ingress, tracing, error-reporting, and debugging systems.

## Image Supply Chain

The repository has a production Dockerfile and binary release automation. A
container release workflow must fulfill the following image deployment contract
before a registry artifact is used:

- The image repository is `ghcr.io/kroderdev/hydra-kratos-login-consent`.
- Deployments refer to an immutable digest, for example
  `ghcr.io/kroderdev/hydra-kratos-login-consent@sha256:<digest>`, rather than a
  moving tag such as `latest`.
- A release workflow publishes a verifiable signature for that exact image
  digest. Verification pins the workflow's documented signing identity and OIDC
  issuer, or an explicitly documented trusted key.
- The release workflow publishes a verifiable SBOM attestation whose subject is
  the exact image digest.
- A release workflow publishes a verifiable build-provenance attestation whose
  subject is the exact image digest and whose source, ref, and builder satisfy
  the organization's release policy.
- A deployment records the selected digest and verification results so a
  rollback can return to the same immutable artifact.

The release workflow must document the verification commands and exact signing
identity. They are not provided by the local Dockerfile build.

```sh
IMAGE=ghcr.io/kroderdev/hydra-kratos-login-consent@sha256:<published-digest>

cosign verify \
  --certificate-identity <documented-release-identity> \
  --certificate-oidc-issuer <documented-release-issuer> \
  "$IMAGE"

```

The workflow must also provide equivalent SBOM and provenance verification
commands for the exact image digest.

Do not replace the digest with a tag after verification. The local Dockerfile
build remains available for source-based deployments; it does not by itself
provide a registry signature or attestation.

## Kubernetes Example

Kubernetes can implement the contract with the following mapping:

- Put non-secret environment values in a `ConfigMap` or equivalent.
- Inject Hydra, policy, and Redis credentials from `Secret` references.
- Run replicas behind a `Service` using the same Redis/Valkey store.
- Configure `/healthz` as the liveness probe and `/readyz` as the readiness
  probe.
- Route only the provider browser endpoints through the ingress or gateway.
- Keep Hydra admin, Kratos admin, and Redis network paths restricted by service
  networking policy.
- Allow at least the provider's 15-second graceful shutdown window when setting
  termination behavior.

The same controls apply when the service runs on another platform; only the
configuration and network primitives change.
