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
   - `force_reauth=true` when OIDC `prompt=login`, `prompt=select_account`, or
     `max_age=0` requires the UI to re-authenticate the browser session
   - `max_age=<seconds>` when Hydra requested a nonnegative `max_age`
   - `aal=<aal>` when a request-specific assurance level was resolved

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
   - `skip_consent=true` when Hydra reports the request as skippable or the
     client's `skip_consent` is configured, and `prompt=consent` is absent
   - `return_to=<provider consent endpoint containing the same flow state>`

4. The UI submits `POST /consent` as a form with `transaction`, `csrf`,
   `decision`, and zero or more `grant_scope` fields. Optional `remember` and
   `remember_for` fields are forwarded to Hydra.
5. The request must include an `Origin` matching the configured external UI
   origin and the browser-state cookie. The provider independently validates the
   transaction, Kratos session, requested scope subset, policy result, and token
   claims.

The UI-provided subject, policy result, and claim values are never trusted.

## OIDC Prompt And Freshness

The provider reads `prompt` and `max_age` from the original authorization URL
that Hydra returns with the login and consent challenge. Supported
space-separated `prompt` values are `login`, `none`, `consent`, and
`select_account`. Unknown values, repeated values, and any list that combines
`none` with another value are rejected with the public `invalid_request` error
and no Hydra rejection. A blank, duplicate, or malformed `prompt` or `max_age`
query parameter from Hydra fails closed as an upstream error.

Login behavior:

- Without a forcing prompt, a login that Hydra reports as skippable (`skip`) and
  that has no request-specific assurance requirement may complete without a UI
  redirect after the provider evaluates the login policy.
- `prompt=login` and `prompt=select_account` prevent silent acceptance and add
  `force_reauth=true` to the UI handoff so the UI re-authenticates the browser
  instead of reusing an existing session. `prompt=consent` has no additional
  effect on the login step.
- `max_age=0` also adds `force_reauth=true`. Every `max_age` is forwarded to the
  UI as `max_age=<seconds>`, and a resolved request-specific assurance level is
  forwarded as `aal=<aal>`.
- `prompt=none` rejects the Hydra login challenge with `login_required` without
  redirecting to the UI whenever interaction would be required: a login Hydra
  does not report as skippable, or any request-specific ACR/AAL requirement.
  A skippable login with no such requirement may complete silently, subject to
  the login policy.

Freshness is revalidated server-side when the login callback completes:

- `prompt=login` requires the Kratos session authentication timestamp to be
  strictly newer than the transaction start.
- `max_age=0` requires the same re-authentication freshness.
- `max_age=N` for `N` greater than zero requires the session age to be at most
  `N` seconds, with fractional ages rounded up to whole seconds.
- A missing, future, or stale authentication timestamp rejects the Hydra login
  challenge with `login_required`.

Consent behavior:

- `prompt=consent` always takes the interactive UI path and suppresses the
  `skip_consent` handoff hint. `prompt=login` has no additional effect on the
  consent step because login freshness is handled during the login flow.
- `prompt=none` rejects the Hydra consent challenge with `consent_required`
  unless Hydra reports the request as skippable or the client's configured
  `skip_consent` is enabled. The provider never accepts consent silently on its
  own; even a skippable request is handed to the external UI.
- `skip_consent=true` is only a display hint. The provider revalidates the
  transaction, CSRF value, browser-state cookie, Kratos session, requested
  scopes and audiences, and policy result when the UI submits `POST /consent`.
  The bundled sample UI still renders the consent form with explicit approve
  and deny actions; it does not submit automatically.

The bundled sample UI translates `force_reauth=true`, and the presence of a
`max_age` handoff, into Kratos `refresh=true`, so Kratos refreshes the browser
session instead of accepting a stale one. `select_account` has no separate
provider-side freshness check; it only prevents silent session acceptance.

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
