# Requirements

## Document Status

This document defines the initial generic requirements for
`hydra-kratos-login-consent`. It is intentionally independent of any
customer-specific application.

## Problem

Ory Hydra does not authenticate end users or provide a complete login and
consent application. It delegates those responsibilities to a login and
consent provider.

This service provides the trusted server-side provider while an external UI
handles browser-facing Kratos flows.

## Goals

- Support Ory Hydra login and consent flows.
- Integrate with Ory Kratos browser sessions.
- Support an external UI hosted on a separate origin.
- Enforce configurable authenticator assurance requirements.
- Keep Hydra and Kratos administrative APIs private.
- Provide an authorization policy boundary without hardcoding an authorization
  datastore.
- Support application-specific token claims.
- Be suitable for a small stateless Kubernetes workload.
- Provide clear security, testing, and operational contracts.

## Non-Goals

- Implementing Ory Kratos itself.
- Implementing Ory Hydra itself.
- Replacing an external Kratos UI.
- Storing identities, passwords, TOTP secrets, or provider credentials.
- Implementing a general IAM administration product.
- Implementing customer-specific applications or authorization.

## Actors

### OAuth Client

An application that starts an OAuth2/OIDC authorization flow, such as a
dashboard or business application.

### Hydra

The OAuth2/OIDC server that owns protocol state and tokens.

### Kratos

The identity and session service that authenticates the operator or user.

### External UI

The browser-facing application that renders Kratos flows. It is treated as an
untrusted client of this service.

### Authorization Policy

An injected policy implementation that decides whether an authenticated subject
may use a particular OAuth client and scope set.

## Login Flow Requirements

- The service MUST accept Hydra login challenges only from configured Hydra
  endpoints.
- The service MUST validate the requested OAuth client.
- The service MUST validate redirect and return URLs against configured
  allowlists.
- The service MUST create a short-lived, single-use browser transaction.
- The service MUST bind every browser transaction to a provider-issued
  browser-state cookie.
- The service MUST redirect the browser to a configured external UI origin.
- The service MUST validate the Kratos session after the browser returns.
- The service MUST support a configurable required AAL.
- The service MUST fail closed when Kratos cannot be reached or the session is
  invalid.
- The service MUST call Hydra admin APIs only from the server side.
- The service MUST accept a Hydra login challenge only after policy approval.
- The service MUST reject an already-used or expired transaction.

## Consent Flow Requirements

- The service MUST retrieve the consent challenge from Hydra admin.
- The service MUST validate the OAuth client and requested scopes.
- The service MUST validate requested token audiences against client and policy
  allowlists.
- The service MUST validate the configured assurance level on every consent
  acceptance path.
- The service MUST not grant scopes that are not allowed for the client.
- The service MUST invoke the authorization policy before accepting consent.
- The service MUST allow the policy to add application-specific ID-token claims.
- The service MUST support explicit rejection with an OAuth error.
- The service MUST not silently grant access when policy evaluation fails.
- The service MAY skip a visual consent page for configured first-party clients,
  but it MUST still evaluate authorization policy.

## Logout Requirements

- The service MUST validate post-logout return URLs.
- The service MUST redirect only to configured external UI or client origins.
- The service MUST not implement an open redirect.
- Logout completion MUST use browser-bound CSRF proof and an external UI Origin
  check.

## External UI Requirements

- The UI MUST receive only opaque transaction/CSRF handles and safe display
  data.
- The UI MUST not receive Hydra admin credentials.
- The UI MUST not be trusted to provide a subject, role, AAL, or authorization
  result.
- The callback MUST be verifiable by the service without trusting UI-provided
  claims.
- Login and consent callbacks MUST include a single-use CSRF proof bound to the
  server-side transaction.
- Cross-origin cookies and CORS behavior MUST be explicitly configured and
  covered by integration tests.
- The UI origin MUST be configured rather than accepted from a request.

## Security Requirements

- All HTTP traffic MUST use TLS outside local development.
- Hydra admin and Kratos admin endpoints MUST be private.
- OAuth client IDs, redirect URIs, and scopes MUST be allowlisted.
- State, nonce, and transaction values MUST be unpredictable and single-use.
- CSRF protection MUST cover state-changing browser endpoints.
- Request bodies and headers MUST have explicit size limits.
- Upstream HTTP clients MUST use connection, response-header, and total request
  timeouts.
- Logs MUST redact cookies, authorization headers, tokens, challenges, and
  provider credentials.
- Errors returned to browsers MUST not disclose upstream credentials or internal
  service details.
- The service MUST use secure cookie attributes for any cookies it creates.
- The service MUST fail closed if policy, Kratos, or Hydra dependencies fail.
- The service MUST expose no generic proxy to Hydra admin or Kratos admin.

## Policy Requirements

The generic core MUST depend on an abstract policy boundary. The policy must be
able to:

- Authorize a login for a subject and OAuth client.
- Authorize consent for a subject, client, and requested scopes.
- Restrict token audiences for that subject, client, and scope set.
- Return claims appropriate for that client and scope set.

The initial default policy MAY be a static allowlist for local development. A
policy implementation MAY later call Keto or another authorization service
without changing the protocol layer.

## Configuration Requirements

The implementation MUST support configuration for:

- Public provider URL.
- External UI URL.
- Hydra public URL.
- Hydra admin URL.
- Kratos public URL.
- Required AAL.
- Allowed OAuth clients.
- Allowed redirect URIs.
- Allowed scopes.
- Allowed token audiences.
- Transaction lifetime.
- Pending transaction quota.
- Environment-specific transport and state-store policy.
- Policy implementation.
- Logging level.

Secrets MUST be supplied at runtime and MUST NOT be committed to the
repository.

## HTTP Surface

The initial public surface is expected to include:

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/login` | Start a Hydra login transaction |
| `GET` | `/login/callback` | Complete the external UI handoff |
| `GET` | `/consent` | Inspect a consent challenge |
| `POST` | `/consent` | Accept or reject consent |
| `GET` | `/logout` | Complete a validated logout flow |
| `POST` | `/logout` | Complete browser-bound logout |
| `GET` | `/healthz` | Liveness check |
| `GET` | `/readyz` | Dependency readiness check |

The exact paths remain subject to the Hydra and external UI callback contract.

## Operational Requirements

- The service MUST support graceful shutdown.
- The service MUST expose liveness and readiness checks.
- The service MUST emit structured logs with request IDs.
- The service SHOULD expose metrics for login, consent, policy, and upstream
  failures.
- The service SHOULD support horizontal replicas without process-local session
  state.
- Any state store MUST be behind an interface and support expiry and replay
  protection.
- Builds MUST be reproducible from a committed Go module lock state.
- The end-to-end provider contract MUST run in CI with isolated Hydra, Kratos,
  policy, and transaction-store fixtures.

## Testing Requirements

The implementation MUST include tests for:

- Valid and invalid Hydra login challenges.
- Invalid clients and redirect URIs.
- Expired and replayed transaction state.
- Invalid Kratos sessions.
- Sessions below the required AAL.
- Policy denial and policy dependency failure.
- Consent scope reduction and rejection.
- Claim filtering by client and scope.
- Logout return URL validation.
- CSRF and request-origin protections.
- Hydra and Kratos upstream timeouts.

Integration tests SHOULD run against pinned Hydra and Kratos containers. Browser
tests SHOULD cover the external UI handoff and a complete OIDC authorization
code flow.

## Acceptance Criteria

The first implementation is acceptable when:

1. A valid Kratos session can complete a Hydra login challenge.
2. A session below the configured AAL is rejected.
3. An unauthorized client or scope is rejected.
4. A policy-approved consent request returns to the OAuth client.
5. No Hydra admin credential is exposed to the browser or external UI.
6. Replay, open-redirect, invalid-state, and CSRF tests pass.
7. The service passes formatting, unit tests, race tests, vet, and static checks.

## Open Decisions

- The in-memory transaction store is reserved for tests and local development.
  Release deployments use a shared Redis/Valkey adapter before running multiple
  replicas.
- The initial browser handoff returns to the provider with the browser's
  configured Kratos session cookie. An explicit one-time session-token handoff
  remains a future adapter option for deployments where cookie scope cannot be
  shared.
- The exact self-hosted Ory Go client versions matching the Hydra and Kratos
  server versions.
- Consent is currently delegated entirely to the external UI. The provider
  remains the source of truth for policy, scope, claims, and Hydra decisions.
