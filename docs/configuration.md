# Configuration

The server loads configuration from environment variables. This document is
the authoritative configuration reference. `.env.example` is a development
example, not a production secret store.

## Environment Rules

`ENVIRONMENT` defaults to `development`. The service treats `development` and
`test` as local environments. Every other value is a secure environment; use
`production` for a production deployment and use a distinct value for each
non-production environment.

Secure environments require HTTPS for the configured HTTP URLs, require the
Redis TLS scheme, reject the in-memory transaction store, and require the
server-side credentials and policy settings described below.

## Variables

| Variable | Default | Required and constraints |
|---|---|---|
| `LISTEN_ADDR` | `:8080` | Address on which the process listens. The process itself serves HTTP; secure deployments provide a TLS-capable front door or sidecar. |
| `LOG_LEVEL` | `info` | `debug`, `info`, `warn`, or `error`. Unknown values use `info`. |
| `ENVIRONMENT` | `development` | Selects local versus secure validation. `production` is the recommended production value. |
| `PUBLIC_URL` | none | Provider URL used to build browser callbacks. It must be an absolute `http` or `https` URL without URL credentials or a fragment; it must use `https` in secure environments. |
| `EXTERNAL_UI_URL` | none | External browser UI handoff URL. It has the same URL requirements as `PUBLIC_URL`. The browser `Origin` used for state-changing UI requests must exactly match its scheme and authority. |
| `HYDRA_ADMIN_URL` | none | Server-side Hydra admin API URL. Keep this endpoint private. It must use `https` in secure environments. |
| `HYDRA_PUBLIC_URL` | none | Hydra public origin used to validate redirects returned by Hydra. It must use `https` in secure environments. |
| `KRATOS_PUBLIC_URL` | none | Server-side base URL for Kratos session validation and readiness. It must use `https` in secure environments. Keep administrative Kratos endpoints private. |
| `KRATOS_SESSION_COOKIE` | `ory_kratos_session` | Name of the browser cookie forwarded to Kratos. This is a cookie name, not a credential. |
| `REQUIRED_AAL` | `aal2` | Minimum authenticator assurance level. Supported values are `aal1`, `aal2`, and `aal3`. |
| `TRANSACTION_TTL` | `5m` | Lifetime of a browser transaction. It must be at least `1s` and no more than `15m`. |
| `MAX_PENDING_TRANSACTIONS` | `10000` | Per-process pending transaction quota. `0` uses the default; negative values are invalid. This is not a shared global quota. |
| `ALLOWED_CLIENTS` | empty object | JSON map of exact OAuth client and token policy allowlists. An empty map causes all client requests to be rejected. See [Client Allowlists](#client-allowlists). |
| `ALLOWED_SUBJECTS` | empty | Comma-separated exact subject IDs used by the static policy backend. An empty value makes the static policy deny every subject. |
| `ALLOWED_SUBJECT_SCOPES` | empty | JSON subject-to-client-to-scope rules for the static policy backend. Required in secure environments when `POLICY_BACKEND=static`; not used by the HTTP policy backend. |
| `POLICY_BACKEND` | `static` | `static` for the local allowlist adapter or `http` for the versioned remote policy adapter. |
| `POLICY_URL` | empty | Complete versioned policy endpoint, required when `POLICY_BACKEND=http`. It must have no URL credentials, query, or fragment and must use `https` in secure environments. |
| `POLICY_AUTH_TOKEN` | empty | Bearer credential sent only to the HTTP policy endpoint. Required when `POLICY_BACKEND=http` in secure environments. |
| `HYDRA_ADMIN_TOKEN` | empty | Bearer credential sent only to Hydra admin requests. Required in secure environments. |
| `STATE_STORE` | `memory` | `memory` for local development and tests or `redis` for shared Redis/Valkey state. Secure environments must use `redis`. |
| `REDIS_URL` | empty | Required when `STATE_STORE=redis`. It must use `redis://` or `rediss://`; secure environments require `rediss://`. TLS certificate verification must not be disabled with `skip_verify`. |
| `REDIS_KEY_PREFIX` | empty | Prefix for transaction keys. Required and non-empty for Redis in secure environments. Use a distinct prefix for each environment and deployment. |

HTTP URL validation rejects embedded credentials and fragments. Redis URLs may
contain credentials, which must be injected and handled as secrets. Secure
environment validation applies to every value except when `ENVIRONMENT` is
exactly `development` or `test` after trimming and lowercasing.

## Client Allowlists

`ALLOWED_CLIENTS` is a JSON object keyed by OAuth client ID. The map key is the
authoritative ID; an optional `id` property must match it. A configured client
must contain at least one `allowed_redirect_uris` value.

The following is a generic shape. Values are examples, not credentials:

```json
{
  "client-id": {
    "allowed_redirect_uris": [
      "https://client.example/callback"
    ],
    "allowed_post_logout_redirect_uris": [
      "https://client.example/signed-out"
    ],
    "allowed_scopes": [
      "openid",
      "profile"
    ],
    "allowed_audiences": [
      "api.example"
    ],
    "skip_consent": false,
    "allowed_id_token_claims": {
      "email": ["profile"]
    },
    "allowed_access_token_claims": {}
  }
}
```

The service applies these rules with exact string matching:

- The Hydra client ID must be present in `ALLOWED_CLIENTS`.
- Every redirect URI returned in the Hydra client registration must appear in
  `allowed_redirect_uris`.
- A requested post-logout redirect URI must appear in
  `allowed_post_logout_redirect_uris`.
- Every requested scope and token audience must appear in its corresponding
  allowlist.
- Claim names are allowed only when their required scopes are present in the
  corresponding token's granted scopes.
- Wildcards, host suffixes, prefixes, and inferred client registrations are not
  supported.

Keep each allowlist unique. `skip_consent` only supplies a safe display hint to
the external UI; it does not bypass client validation or policy evaluation.

## Policy Backends

### Static

`static` is the default and is intended for local development and tests. It
requires a subject in `ALLOWED_SUBJECTS`; the provider separately requires the
subject's client to be in `ALLOWED_CLIENTS`. In a secure environment,
`ALLOWED_SUBJECT_SCOPES` must be non-empty and has this shape:

```json
{
  "subject-id": {
    "client-id": ["openid", "profile"]
  }
}
```

The static scope rules restrict the scopes selected for consent. Client scope
and audience allowlists are still enforced independently. `ALLOWED_SUBJECT_SCOPES`
is not required, read, or consulted when `POLICY_BACKEND=http` is selected.

### HTTP

`http` sends the provider-validated login or consent context to the complete
versioned `POLICY_URL`, for example:

```text
https://policy.example/v1/authorize
```

`POLICY_AUTH_TOKEN` is sent as a bearer token and never to the external UI. The
remote response must explicitly identify contract version `v1`, allow or deny
the request, and return effective scopes and audiences. Remote grants may only
reduce the locally validated grants. Missing, malformed, oversized, denied-with-
grants, or unavailable policy responses fail closed.

The HTTP policy contract is specified in [policy-contract.md](policy-contract.md).

## State Store

Browser transactions are short-lived, opaque, single-use records. The Redis
adapter stores them with expiry and atomically consumes them, so every replica
must use the same Redis or Valkey service. Redis/Valkey is required in secure
environments and for any multi-replica deployment. The in-memory store is only
for local development and tests and must not be used for release deployments.

## Secret Handling

Inject `HYDRA_ADMIN_TOKEN`, `POLICY_AUTH_TOKEN`, and any credential-bearing
`REDIS_URL` at runtime through the deployment's secret mechanism. Do not commit
them, put them in `.env.example`, copy them into an image, or pass them to the
external UI. Use separate credentials and Redis key prefixes per environment.

The service and surrounding access logs must not record authorization headers,
Hydra admin tokens, policy tokens, Redis passwords or URLs containing passwords,
Kratos cookies, browser-state cookies, CSRF tokens, transaction handles, or
Hydra challenges. See [deployment.md](deployment.md#secrets-and-logging).

## Generic Secure Shape

This example intentionally omits secret values and is not a complete client
configuration:

```text
ENVIRONMENT=production
PUBLIC_URL=https://provider.example
EXTERNAL_UI_URL=https://ui.example/login
HYDRA_ADMIN_URL=https://hydra-admin.internal
HYDRA_PUBLIC_URL=https://hydra.example
KRATOS_PUBLIC_URL=https://kratos.internal
STATE_STORE=redis
REDIS_URL=rediss://redis.internal:6380/0
REDIS_KEY_PREFIX=provider-production:transaction:
POLICY_BACKEND=http
POLICY_URL=https://policy.example/v1/authorize
```

Supply `ALLOWED_CLIENTS`, `HYDRA_ADMIN_TOKEN`, and `POLICY_AUTH_TOKEN` through
the deployment configuration or secret mechanism. See [deployment.md](deployment.md)
for network, image, rollout, and probe requirements.
