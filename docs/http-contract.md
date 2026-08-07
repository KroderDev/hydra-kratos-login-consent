# HTTP And External UI Contract

The provider exposes only the browser-facing flow endpoints. Hydra admin and
Kratos APIs are never proxied to the browser or external UI.

## Login

1. Hydra redirects the browser to `GET /login?login_challenge=...`.
2. The provider retrieves and validates the challenge through Hydra admin.
3. The provider creates a short-lived, single-use transaction handle and binds
   it to a provider browser-state cookie.
4. The browser is redirected to the configured external UI with:

   - `flow=login`
   - `transaction=<opaque handle>`
   - `csrf=<opaque single-use token>`
   - `return_to=<provider callback containing the same flow state>`

   The callback query is nested inside `return_to`, so its `?`, `&`, and `=`
   separators are percent-encoded in the external UI URL. Treat `return_to` as
   an opaque URL value and construct both URL layers with URL APIs. Do not
   concatenate the nested query string or encode it more than once.

5. The external UI completes the Kratos browser flow and sends the browser to
   `GET /login/callback?transaction=...&csrf=...&flow=login`.
6. The provider validates the browser-state cookie, Kratos session and AAL,
   evaluates policy, and
   accepts or rejects the original Hydra challenge.

The Hydra challenge and any provider credentials are never included in the UI
redirect.

## Consent

1. Hydra redirects the browser to `GET /consent?consent_challenge=...`.
2. The provider validates the client, requested scopes and audiences, creates a
   single-use transaction bound to a browser-state cookie, and redirects to the
   external UI.
3. The UI receives safe display data in addition to the opaque transaction:

   - `flow=consent`
   - `transaction=<opaque handle>`
   - `csrf=<opaque single-use token>`
   - `client_name=<display name>`
   - `scope=<space-separated validated scopes>`
   - `skip_consent=true` when configured first-party policy permits an automatic UI submission
   - `return_to=<provider consent endpoint containing the same flow state>`

4. The UI submits `POST /consent` as a form with `transaction`, `csrf`,
   `decision`, and zero or more `grant_scope` fields. Optional `remember` and
   `remember_for` fields are forwarded to Hydra.
5. The request must include an `Origin` matching the configured external UI
   origin and the browser-state cookie. The provider independently validates the
   transaction, Kratos session, requested scope subset, policy result, and token
   claims.

The UI-provided subject, policy result, and claim values are never trusted.

## Logout

`GET /logout?logout_challenge=...` validates the client and post-logout return
URI, then starts a browser-bound external UI handoff. The UI completes it with
`POST /logout` as a form containing `transaction` and `csrf`, with an `Origin`
matching the configured external UI origin. Only then does the provider accept
the Hydra logout challenge.

## Operational Endpoints

- `GET /healthz` reports process liveness.
- `GET /readyz` checks Hydra and Kratos readiness and also checks the configured
  Redis/Valkey store when `STATE_STORE=redis`. It does not call the HTTP policy
  endpoint.

All responses set no-store and browser hardening headers. Error bodies contain
stable public error codes rather than upstream details.
