# Remote Policy Contract

The HTTP policy backend uses the versioned `v1` authorization endpoint:

```text
POST <POLICY_URL>
```

`POLICY_URL` must point to the complete versioned endpoint, for example
`https://policy.example/v1/authorize`. Requests and responses use JSON.

## Authentication

The provider sends the configured `POLICY_AUTH_TOKEN` as a bearer token:

```text
Authorization: Bearer <token>
```

The token is never sent to the external UI, included in logs, or returned in an
error. HTTPS is required outside development and test environments.

## Request

The request contains provider-validated identity, client, consent, and session
assurance context:

```json
{
  "version": "v1",
  "operation": "consent",
  "issuer": "https://issuer.example",
  "subject": "operator-1",
  "client_id": "example-client",
  "requested_scopes": ["openid", "profile"],
  "granted_scopes": ["openid"],
  "requested_audiences": ["example-api"],
  "aal": "aal2",
  "amr": ["pwd", "totp"]
}
```

`operation` is `login` or `consent`. Login requests send empty scope,
audience, and assurance-method arrays when no authenticated Kratos session is
available. Consent `granted_scopes` contains the user's selected scopes.

`issuer` is the deployment-configured issuer for the operator identity realm.
It is not derived from browser input, the OAuth client, or policy request data.
The policy service must treat it as part of the canonical `(issuer, subject)`
identity key.

The policy service must treat all values as authorization input, not as proof
of authentication. The provider has already validated the Hydra challenge,
OAuth client, scopes, audiences, and Kratos session where applicable.

## Response

An allowed consent response contains explicit effective grants:

```json
{
  "version": "v1",
  "allowed": true,
  "granted_scopes": ["openid"],
  "granted_audiences": ["example-api"],
  "claims": {
    "id_token": {
      "email": "operator@example.com"
    },
    "userinfo": {},
    "access_token": {}
  }
}
```

Denied responses must contain `allowed: false` and empty grants. Claims are
optional for allowed responses and are always filtered through the configured
client claim allowlists before reaching Hydra. `claims.id_token`,
`claims.userinfo`, and `claims.access_token` are independent optional objects;
the provider never copies a claim from one destination to another. The
provider derives optional identity claims locally from the validated Kratos
session after this policy decision is allowed; identity source data and
mappings are never sent to the policy service.

The provider rejects a response when:

- `version` is missing or is not `v1`.
- `allowed` or either grant list is missing or has the wrong type.
- A grant is empty, duplicated, or expands the locally validated request.
- A denied response contains grants or claims.
- The response is oversized, malformed, truncated, or has trailing JSON.

Policy grants can only reduce the user's selected scopes and the requested
audiences. They can never add either value.

## Errors And Timeouts

The adapter uses the shared bounded HTTP client. Its default limits are a
10-second total request timeout, 3-second dial and TLS handshake timeouts, and
an 8-second response-header timeout. It does not follow redirects or retry
authorization requests.

Any connection failure, timeout, non-2xx response, oversized response, or
malformed decision maps to an internal upstream failure. The application fails
closed and exposes only a stable temporary-unavailability error at its public
HTTP boundary.

The static policy implements the same core port and remains the default for
development and tests. It returns the locally validated scopes and audiences
as its effective grants. `ALLOWED_SUBJECTS` and the configured client IDs form
its subject and client allowlists. In a secure environment, static composition
also requires non-empty `ALLOWED_SUBJECT_SCOPES`, whose subject/client/scope
rules restrict the scopes selected for consent.

When `POLICY_BACKEND=http` is selected, `POLICY_URL` must be the complete
versioned endpoint, `POLICY_ISSUER` must identify the configured operator realm,
and `POLICY_AUTH_TOKEN` is required outside development and test. The HTTP backend does not read `ALLOWED_SUBJECT_SCOPES`; local client,
redirect, scope, audience, and claim allowlists still apply before and after the
remote decision.

## Identity Claims And Scopes

Identity claim mappings are configured with `OIDC_IDENTITY_CLAIM_MAPPINGS`, not
in this response. They can read only sanitized Kratos `traits` and
`metadata_public` values through exact RFC 6901 JSON Pointers. `email` and
`email_verified` require the `email` scope, while profile claims such as
`name`, `given_name`, `family_name`, and `picture` require `profile`. The
corresponding destination allowlist (`allowed_id_token_claims`,
`allowed_userinfo_claims`, or `allowed_access_token_claims`) is still required,
and identity claims remain opt-in for every destination.

Configured identity mapping names are authoritative: same-name policy claims
are suppressed so a policy response cannot replace a validated identity value.
Protocol-owned claims such as `sub`, `iss`, `aud`, `exp`, `iat`, `nbf`, `nonce`,
`acr`, `amr`, and `azp` are rejected from both mapping and client policy
allowlist configuration. Hydra remains responsible for protocol claims.

The pinned Hydra v26.2.0 consent API has no separate `userinfo` session field,
and its `/userinfo` response is derived from `session.id_token`. If filtering
produces a non-empty UserInfo object, the Hydra adapter fails closed with an
upstream error before sending the acceptance request rather than silently
dropping or relocating those claims. Do not return `claims.userinfo` or configure
`allowed_userinfo_claims` until the deployed Hydra version supports a distinct
persisted UserInfo session object.
