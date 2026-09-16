# Integration Testing

The repository has four test layers. They have different dependencies and are
not interchangeable.

## Fixture Integration

The `integration` build tag runs `internal/e2e/e2e_test.go`. It uses
`httptest`, miniredis, and adapter fakes to exercise the provider HTTP contract
quickly and deterministically:

```sh
make e2e
```

This layer is suitable for every pull request and does not require Docker,
Hydra, or Kratos processes.

## Real Services And OIDC Smoke

The `integration,realstack` build tags run
`internal/e2e/realstack_test.go`. `docker-compose.realstack.yml` pins Hydra
2.2.0, Kratos 1.3.1, Redis 7.4.2, and the local policy/UI/provider images.
The documented clean-run command is:

```sh
make integration-real
```

The command removes the named SQLite volumes on exit so client registration,
identities, and remembered consent do not leak between runs. Override the
`REALSTACK_CLIENT_SECRET`, `REALSTACK_PASSWORD`, `REALSTACK_BASIC_PASSWORD`,
and `REALSTACK_POLICY_TOKEN` variables when needed. These values are test
credentials only; do not use production credentials or commit them.

The real-stack test drives the browser handoff with a cookie jar and a fixed
registered callback on `127.0.0.1:5555`. It covers authorization-code PKCE
with S256, state, nonce, `prompt=login`, `max_age`, `acr_values`, password
AMR/AAL claims, requested and granted scopes, identity and policy claims,
unauthorized claim filtering, remembered consent, rejected consent,
policy-rejected login, single-use consent, redirect/client validation, unknown
challenges, and post-logout redirect handling. It never logs credentials,
challenges, codes,
tokens, or TOTP material.

The OIDC assertions are intentionally independent of the Hydra adapter. The
test discovers the issuer with `github.com/coreos/go-oidc/v3/oidc`, exchanges
the code with `golang.org/x/oauth2`, and verifies the signed ID token through
the discovery keys.

## OpenID Foundation Conformance Suite

The official suite is an external dependency and is not run on every pull
request. Use a disposable HTTPS deployment or a suite-visible tunnel, then
register a static client whose callback and post-logout callback are reachable
from the suite. Configure matching exact entries in `ALLOWED_CLIENTS`, Hydra,
and the policy service. The current local real stack is an HTTP localhost
smoke environment and is not a conformance endpoint.

Pin the conformance-suite repository to a reviewed commit and run its official
Python test-plan runner:

```sh
git clone https://gitlab.com/openid/conformance-suite.git
cd conformance-suite
git checkout <reviewed-commit>
export CONFORMANCE_SERVER=https://<suite-host>/
python scripts/run-test-plan.py --no-parallel \
  'oidcc-basic-certification-test-plan[server_metadata=discovery][client_registration=static_client]' \
  /path/to/hydra-oidcc.json
```

`hydra-oidcc.json` is suite-version-specific and must contain the disposable
client and reachable callback configuration. Keep it in a secret store when
it contains client credentials. The repository provides a manual/nightly
workflow at `.github/workflows/conformance.yml`; enable it only after setting
the repository configuration described in that workflow. The workflow does
not silently claim conformance when the external suite is not configured.
