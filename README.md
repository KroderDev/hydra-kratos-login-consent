# Hydra Kratos Login Consent

Generic Go login and consent provider for [Ory Hydra](https://www.ory.sh/hydra/)
and [Ory Kratos](https://www.ory.sh/kratos/).

Hydra delegates end-user authentication and consent to an application. This
project provides that server-side integration while allowing the actual login
and MFA screens to remain in a separate external UI.

## Responsibilities

The service:

- Receive Hydra login and consent challenges.
- Redirect the browser to an external Kratos UI.
- Validate the resulting Kratos session.
- Enforce a configurable authenticator assurance level.
- Apply an application-supplied authorization policy.
- Accept or reject Hydra challenges through the private Hydra admin API.
- Add only approved, application-specific token claims.

The service does not:

- Store passwords, TOTP secrets, or OAuth provider credentials.
- Replace Kratos, Hydra, or Keto.
- Own application user interfaces.
- Contain customer-specific domains or application-specific policy in its
  generic core.

## Architecture

```mermaid
flowchart TD
    client["OAuth/OIDC client"] --> hydraPublic["Hydra public API"]
    hydraPublic --> provider["Hydra login and consent provider"]
    provider -->|private admin API| hydraAdmin["Hydra admin API"]
    provider -->|private session API| kratos["Kratos session API"]
    provider --> policy["Authorization policy"]
    provider -->|browser redirect| ui["External Kratos UI<br/>Untrusted"]
    ui -->|browser callback| provider
```

The external UI is a browser-facing client. It never receives Hydra admin
credentials and is not trusted to make authorization decisions.

## Documentation

- Read the [full documentation](docs/README.md), including requirements,
  architecture, trust boundaries, and the HTTP contract.

## Layout

```text
cmd/server/                         composition root and graceful shutdown
internal/core/domain/               provider-owned models and invariants
internal/core/ports/                driving and driven port contracts
internal/core/application/          login, consent, and logout flows
internal/core/config/               validated configuration contract
internal/config/                    environment configuration loader
internal/adapters/inbound/http/     HTTP security boundary
internal/adapters/outbound/         Hydra, Kratos, policy, and state adapters
```

## Configuration

The server reads configuration from environment variables:

| Variable | Purpose |
|---|---|
| `PUBLIC_URL` | Public provider URL. |
| `EXTERNAL_UI_URL` | Configured external login/consent UI URL. |
| `HYDRA_ADMIN_URL` | Private Hydra admin API URL. |
| `HYDRA_PUBLIC_URL` | Hydra public origin used to validate returned redirects. |
| `KRATOS_PUBLIC_URL` | Kratos public session API URL. |
| `KRATOS_SESSION_COOKIE` | Kratos browser cookie name, default `ory_kratos_session`. |
| `REQUIRED_AAL` | Minimum assurance level, default `aal2`. |
| `TRANSACTION_TTL` | Browser transaction lifetime, default `5m`. |
| `ALLOWED_CLIENTS` | JSON client and scope allowlist. |
| `ALLOWED_SUBJECTS` | Comma-separated subjects for the local policy adapter. |
| `HYDRA_ADMIN_TOKEN` | Optional runtime bearer token for Hydra admin requests. |
| `STATE_STORE` | Currently only `memory`; production mode rejects it. |
| `ENVIRONMENT` | Set to `production` to reject the local memory store. |

`ALLOWED_CLIENTS` must include exact redirect URI and scope allowlists. Example:

```json
{
  "example-client": {
    "allowed_redirect_uris": ["https://client.example/callback"],
    "allowed_post_logout_redirect_uris": ["https://client.example/"],
    "allowed_scopes": ["openid", "profile"]
  }
}
```

## Development

Run the checks directly or through the Makefile targets:

```text
gofmt -w .
go test ./...
go test -race ./...
go vet ./...
golangci-lint run ./...
govulncheck ./...
```

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
