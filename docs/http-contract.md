# HTTP And External UI Contract

The provider exposes only the browser-facing flow endpoints. Hydra admin and
Kratos APIs are never proxied to the browser or external UI.

## Login

1. Hydra redirects the browser to `GET /login?login_challenge=...`.
2. The provider retrieves and validates the challenge through Hydra admin.
3. The provider creates a short-lived, single-use transaction handle.
4. The browser is redirected to the configured external UI with:

   - `flow=login`
   - `transaction=<opaque handle>`
   - `return_to=<fixed provider callback>`

5. The external UI completes the Kratos browser flow and sends the browser to
   `GET /login/callback?transaction=...`.
6. The provider validates the Kratos session and AAL, evaluates policy, and
   accepts or rejects the original Hydra challenge.

The Hydra challenge and any provider credentials are never included in the UI
redirect.

## Consent

1. Hydra redirects the browser to `GET /consent?consent_challenge=...`.
2. The provider validates the client and requested scopes, creates a single-use
   transaction, and redirects to the external UI.
3. The UI receives safe display data in addition to the opaque transaction:

   - `flow=consent`
   - `transaction=<opaque handle>`
   - `client_name=<display name>`
   - `scope=<space-separated validated scopes>`
   - `return_to=/consent`

4. The UI submits `POST /consent` as a form with `transaction`, `decision`, and
   zero or more `grant_scope` fields.
5. The request must include an `Origin` matching the configured external UI
   origin. The provider independently validates the transaction, Kratos
   session, requested scope subset, policy result, and token claims.

The UI-provided subject, policy result, and claim values are never trusted.

## Logout

`GET /logout?logout_challenge=...` validates the client and post-logout return
URI before completing the Hydra logout challenge.

## Operational Endpoints

- `GET /healthz` reports process liveness.
- `GET /readyz` checks configured Hydra and Kratos readiness adapters.

All responses set no-store and browser hardening headers. Error bodies contain
stable public error codes rather than upstream details.
