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
    "access_token": {}
  }
}
```

Denied responses must contain `allowed: false` and empty grants. Claims are
optional for allowed responses and are always filtered through the configured
client claim allowlists before reaching Hydra.

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
as its effective grants.
