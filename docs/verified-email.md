# Verified email ownership

`email_verified` is derived only from the server-validated Kratos session's
`identity.verifiable_addresses`: an address must use `via=email`, have
`verified=true` and `status=completed`, and match the emitted email. Traits,
public metadata, policy claims, and browser input cannot assert verification.

Each destination (UserInfo, ID token, access token) must explicitly allow both
`email` and `email_verified`, and the effective consent must grant `email` scope.
Without a matching completed verification the emitted value is false; without
the destination email or scope it is omitted. Existing tokens retain their
original consent session; users must authenticate again after enabling claims.

For invitation acceptance, allow these claims on UserInfo and let the API
gateway obtain them directly from Hydra with the authenticated access token.
Do not infer ownership from the business application's editable profile email.
