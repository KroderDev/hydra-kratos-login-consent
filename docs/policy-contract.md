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
  "granted_audiences": ["example-api"],
  "aal": "aal2",
  "amr": ["pwd", "totp"]
}
```

`operation` is `login` or `consent`. Login requests send empty scope and
audience arrays; on a Hydra-skipped login without a validated Kratos session,
`aal` is empty and `amr` is `[]`. Consent `granted_scopes` and
`granted_audiences` contain the user's selected scopes and audiences (or all
requested audiences when none were selected explicitly).

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
and `POLICY_AUTH_TOKEN` is required outside development and test. The HTTP
backend does not read `ALLOWED_SUBJECTS` or `ALLOWED_SUBJECT_SCOPES`; local
client, redirect, scope, audience, and claim allowlists still apply before and
after the remote decision.

## Recipe: Self-Service Onboarding

To allow newly registered users to use an approved OAuth client without adding
each subject to a deployment allowlist, select `POLICY_BACKEND=http`. This is a
deployment policy decision, not a default OAuth permission. Keep exact
`ALLOWED_CLIENTS` entries with explicit `allowed_redirect_uris`,
`allowed_scopes`, and `allowed_audiences` (see the
[client allowlists](configuration.md#client-allowlists)), and configure
`POLICY_URL`, `POLICY_ISSUER`, `POLICY_AUTH_TOKEN`, and the provider's
`REQUIRED_AAL`. The policy service uses the canonical `(issuer, subject)` pair
and its own approved-client and grant rules; it does not need to pre-enroll
every subject.

For example, with `example-client` and its exact redirect URI
`https://client.example/callback` in `ALLOWED_CLIENTS`, approved scopes
`openid` and `profile`, and approved audience `example-api`, a policy service
can implement these rules:

1. For **both** operations, require `version: "v1"`, the expected issuer, a
   non-empty subject, and the exact approved `client_id`. If account
   verification, suspension, or tenant membership affects eligibility, look up
   those facts in an authoritative identity or membership source using
   `(issuer, subject)`. Deny an unknown, suspended, or otherwise ineligible
   account; an arbitrary subject string is not evidence of eligibility. Treat
   unavailable account state as a denial or service error, not approval.
2. For **login**, allow an eligible subject for that client and return the
   required empty grant arrays. For **consent**, intersect the user's
   `granted_scopes` and `granted_audiences` with the policy's approved scopes
   and audiences; return only those effective grants. Deny if a required scope
   or audience cannot be granted. Never add a scope the user did not select or
   an audience the request did not contain. Apply any policy-specific AAL/AMR
   rules to the supplied assurance context; do not infer assurance from the
   subject alone.

A first interactive login for a new, eligible user can send:

```json
{
  "version": "v1",
  "operation": "login",
  "issuer": "https://issuer.example",
  "subject": "new-user-id",
  "client_id": "example-client",
  "requested_scopes": [],
  "granted_scopes": [],
  "requested_audiences": [],
  "granted_audiences": [],
  "aal": "aal2",
  "amr": ["pwd", "totp"]
}
```

The corresponding policy response is:

```json
{
  "version": "v1",
  "allowed": true,
  "granted_scopes": [],
  "granted_audiences": []
}
```

After the user selects `openid` and `profile` for consent, the provider can
send (the client also allows `email`, but the user did not select it):

```json
{
  "version": "v1",
  "operation": "consent",
  "issuer": "https://issuer.example",
  "subject": "new-user-id",
  "client_id": "example-client",
  "requested_scopes": ["openid", "profile", "email"],
  "granted_scopes": ["openid", "profile"],
  "requested_audiences": ["example-api"],
  "granted_audiences": ["example-api"],
  "aal": "aal2",
  "amr": ["pwd", "totp"]
}
```

If this policy approves only `openid` for that account, it responds with a
subset of the user's selection and of the requested audience:

```json
{
  "version": "v1",
  "allowed": true,
  "granted_scopes": ["openid"],
  "granted_audiences": ["example-api"]
}
```

A denial for either operation has no claims and uses this response:

```json
{
  "version": "v1",
  "allowed": false,
  "granted_scopes": [],
  "granted_audiences": []
}
```

Both grant arrays are required even for login and denial; optional claims must
follow the destination-specific allowlists and the
[identity claim rules](#identity-claims-and-scopes).

The provider validates Hydra challenges, the configured client's exact ID and
registered redirect URIs, requested scopes and audiences against its client
allowlists, transaction and browser binding, Kratos session and subject on
interactive callbacks, and required assurance. It checks that consent policy
grants do not expand the user's selection or requested audiences. The policy
service decides whether this identity may use this client and which of those
grants are eligible under deployment rules. Redirect URIs are not sent to the
policy service; keep the provider's exact redirect allowlist in force.

Remembering login or consent does not bypass authorization. When a Hydra login
is skippable **and** no assurance or prompt requires interaction, the provider
calls `login` policy with Hydra's subject before silently accepting it; that
path has no newly validated Kratos session and sends empty `aal` and `amr`.
The configured `REQUIRED_AAL` (default `aal2`) requires the interactive path
even when Hydra reports `skip`; the provider then validates the Kratos session
and calls login policy on completion. A policy requiring current verification
or suspension state must check its authoritative source on either call (and
deny when it cannot), rather than assuming a remembered login is sufficient.
Skippable consent still goes through the UI handoff and the provider validates
the Kratos session and calls `consent` policy on acceptance.
`skip_consent=true` is only a UI hint, not a policy bypass. See
[OIDC prompt and freshness](http-contract.md#oidc-prompt-and-freshness).

To migrate from per-subject `static` rules, retain the provider's exact client,
redirect, scope, audience, and assurance settings; deploy the HTTP policy
service with equivalent client and grant restrictions, then switch to
`POLICY_BACKEND=http` with the versioned URL, issuer, and runtime bearer
credential. `ALLOWED_SUBJECTS` and `ALLOWED_SUBJECT_SCOPES` no longer apply to
the HTTP adapter. Before rollout, test a newly registered eligible user on an
approved client, an ineligible or suspended user (including remembered login),
an unapproved client or redirect, and a disallowed scope or audience. Test that
the service never returns grants beyond user selection and that policy
timeouts, non-2xx responses, malformed responses, and unavailable eligibility
data fail closed. The provider does not probe policy on `/readyz`; monitor the
policy service separately and expect authorization to be temporarily
unavailable during an outage.

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
