# OpenID Foundation Conformance

The repository includes a non-interactive OIDC discovery gate for the OpenID
Foundation conformance suite release `release-v5.2.4`. It creates the
`oidcc-config-certification-test-plan`, runs
`oidcc-discovery-endpoint-verification`, checks both the module status and
result, and deletes the temporary plan after the run.

The gate is run by
[`scripts/conformance-discovery.sh`](../scripts/conformance-discovery.sh) and
by `.github/workflows/conformance.yml` on a nightly schedule, published
releases, or a manual dispatch.

## Configuration

Configure these values in the repository or shell environment:

| Variable | Requirement |
|---|---|
| `CONFORMANCE_TOKEN` | Short-lived bearer token for the suite API; store it as a repository secret. |
| `CONFORMANCE_DISCOVERY_URL` | HTTPS URL ending exactly in `/.well-known/openid-configuration`; store it as a repository variable or provide it to a manual run. |
| `CONFORMANCE_SERVER` | HTTPS suite API base URL; defaults to `https://www.certification.openid.net`. |

Run the discovery gate locally without printing the token or response files:

```sh
CONFORMANCE_SERVER=https://www.certification.openid.net \
CONFORMANCE_DISCOVERY_URL=https://oidc.example/.well-known/openid-configuration \
CONFORMANCE_TOKEN="$CONFORMANCE_TOKEN" \
bash scripts/conformance-discovery.sh
```

The script keeps API responses in a private temporary directory, does not
write results to the repository, and removes its plan and temporary files on
exit. Do not use shell tracing, verbose curl output, or ordinary CI artifacts
for this command.

## Target Requirements

The disposable real stack is not a remote conformance target. Its issuer is
loopback HTTP (`http://127.0.0.1:4444/`), which is not reachable by the remote
suite and is not suitable for an HTTPS discovery check. A deployed target must
provide a trusted HTTPS facade, publish the matching discovery URL, and route
Hydra's login, consent, and logout callbacks to the bridge. Keep the facade,
issuer, redirect URIs, and browser callback origins consistent.

The discovery gate is intentionally non-interactive. It does not claim that
the full authenticated OpenID Provider plan has run against the disposable
stack.

## Full Basic OP Plan

Run the full plan manually only after the target has a trusted public HTTPS
facade and the suite's browser interaction has been reviewed for credential
handling. Use the pinned release and the static-client plan:

```text
oidcc-basic-certification-test-plan[server_metadata=discovery][client_registration=static_client]
```

Use a unique alias and register the exact suite callback with both static
clients:

```text
https://<suite-host>/test/a/<alias>/callback
```

The plan configuration has no outer wrapper:

```json
{
  "alias": "unique-alias",
  "server": {
    "discoveryUrl": "https://oidc.example/.well-known/openid-configuration"
  },
  "client": {
    "client_id": "<basic-client-id>",
    "client_secret": "<basic-client-secret>"
  },
  "client_secret_post": {
    "client_id": "<post-client-id>",
    "client_secret": "<post-client-secret>"
  }
}
```

Do not register a wildcard callback. Negative conformance tests intentionally
use altered redirect URIs. Keep client secrets, end-user credentials, suite
tokens, private keys, browser logs, and exported results outside source
control and CI logs. The suite's BrowserControl flow can log literal test
passwords, so an unattended authenticated job requires an explicit redaction
and isolated-credential design before it can be enabled.

## Pinned Suite Images

The tagged prebuilt suite compose file is
`release-v5.2.4/docker-compose-prebuilt.yml`. If it is used locally, preserve
the `nginx` to `server:8080` service contract and pin the release images:

| Image | Digest |
|---|---|
| `registry.gitlab.com/openid/conformance-suite:release-v5.2.4` | `sha256:3a2615ed95a7f3bb92d545b4c65c0268f82a3893d6cd97fd98fd8e44eb15d81f` |
| `registry.gitlab.com/openid/conformance-suite/nginx:release-v5.2.4` | `sha256:43d34ca84e30669ebb30c5cdeb80b3f90bea0f5c47a446e915d843bd7dd3cf04` |

The upstream compose defaults MongoDB to the mutable tag `mongo:6.0.13`.
Override it with the architecture-specific digest before starting a local
fixture: Linux amd64 uses
`sha256:01ac386c1c55e0f26ae1a516383baac2f29937eefe4b6276f8def33d4016e6bd`
and Linux arm64 uses
`sha256:ba69f4aba491d2a4e423a18617e5287752a2b10e1c69d7d5d73a9633b5a533d4`.
The upstream self-signed certificate and dev profile are for local use only;
they are not a public conformance deployment.
