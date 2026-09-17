# Real Hydra/Kratos Integration Stack

The real-stack tests run Hydra, Kratos, Redis, the provider, the policy
fixture, and a browser-facing Kratos UI with Docker Compose. The test also acts
as an independent OIDC relying party: it uses authorization-code PKCE with
`S256`, validates state and nonce, verifies the ID token, checks claims and
assurance values, exercises remembered consent, replay protection, prompt
errors, and logout.

This stack is disposable. It uses seeded test identities and destroys its
SQLite volumes after each run. Do not point it at application data or reuse its
secrets in another environment.

## Prerequisites

- Docker Engine with the Compose plugin
- Go version from `go.mod`
- OpenSSL, used by the Make target to generate runtime-only secrets

## Run The Test

The Make target generates secrets in the shell, uses provider port `18080` to
avoid the usual application port `8080`, starts the pinned images, runs the
tagged tests, and removes the containers and volumes on exit:

```sh
make e2e-realstack
```

Set `REALSTACK_PROVIDER_PORT` to another free loopback port when needed:

```sh
REALSTACK_PROVIDER_PORT=28080 make e2e-realstack
```

The target accepts the runtime variables below when a caller needs to provide
them. If a value is unset, it generates a random value for that invocation.
No value is written to the repository or printed by the target.

| Variable | Used by |
|---|---|
| `REALSTACK_HYDRA_SYSTEM_SECRET` | Hydra system secret |
| `REALSTACK_HYDRA_PAIRWISE_SALT` | Hydra pairwise subject identifiers |
| `REALSTACK_CLIENT_SECRET` | OIDC test client |
| `REALSTACK_KRATOS_COOKIE_SECRET` | Kratos session cookies |
| `REALSTACK_KRATOS_CIPHER_SECRET` | Kratos encrypted values |
| `REALSTACK_PASSWORD` | Seeded operator identity |
| `REALSTACK_BASIC_PASSWORD` | Seeded denied identity |
| `REALSTACK_POLICY_TOKEN` | Provider-to-policy authentication |
| `REALSTACK_PROVIDER_PORT` | Host port for the provider, default `18080` in the Make target |

The Compose file itself defaults the provider port to `8080`; use the Make
target or set `REALSTACK_PROVIDER_PORT` explicitly when running Compose
directly. The UI, Kratos public API, Hydra public API, and OIDC callback use
host ports `3000`, `4433`, `4444`, and `5555` respectively.

## Direct Compose Use

When not using Make, export all required secrets with a runtime secret
mechanism, set a free provider port, and always clean the disposable project:

```sh
export REALSTACK_HYDRA_SYSTEM_SECRET="$(openssl rand -hex 32)"
export REALSTACK_HYDRA_PAIRWISE_SALT="$(openssl rand -hex 32)"
export REALSTACK_CLIENT_SECRET="$(openssl rand -hex 32)"
export REALSTACK_KRATOS_COOKIE_SECRET="$(openssl rand -hex 16)"
export REALSTACK_KRATOS_CIPHER_SECRET="$(openssl rand -hex 16)"
export REALSTACK_PASSWORD="$(openssl rand -hex 16)"
export REALSTACK_BASIC_PASSWORD="$(openssl rand -hex 16)"
export REALSTACK_POLICY_TOKEN="$(openssl rand -hex 32)"
export REALSTACK_PROVIDER_PORT=18080

docker compose -p hydra-realstack -f docker-compose.realstack.yml down -v --remove-orphans
docker compose -p hydra-realstack -f docker-compose.realstack.yml up -d --build --wait
go test -tags=integration,realstack -count=1 -shuffle=on ./internal/e2e
docker compose -p hydra-realstack -f docker-compose.realstack.yml down -v --remove-orphans
```

If the test command is interrupted, run the final `down` command manually.
Never log the exported values, OAuth challenges, cookies, tokens, or Kratos
authentication secrets.
