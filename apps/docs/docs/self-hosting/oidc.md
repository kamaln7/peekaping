---
sidebar_position: 2
---

# OIDC login

Peekaping has a single admin account. OIDC lets that admin sign in through an OpenID Connect provider (OP) instead of with a password. It is not SSO with user provisioning: the OP decides who may be the admin (restrict the client to a user or group there), and Peekaping maps that identity onto its one account.

Password login keeps working whether or not OIDC is configured.

## Configuration

OIDC is configured on the API server through environment variables. They are static config rather than settings, because the login page must know whether OIDC is on before anyone is signed in.

| Variable | Default | Description |
|----------|---------|-------------|
| `OIDC_ISSUER` | unset (OIDC off) | Must equal the `issuer` the OP advertises, byte for byte. Discovery is read from `{issuer}/.well-known/openid-configuration`. |
| `OIDC_CLIENT_ID` | unset | Client ID registered at the OP. Unset selects [Client ID Metadata Document](#b-client-id-metadata-document) mode. |
| `OIDC_CLIENT_SECRET` | unset | Unset: public client (PKCE only). Set: `client_secret_basic` plus PKCE. Not allowed without `OIDC_CLIENT_ID`. |
| `OIDC_SCOPES` | `openid email` | Space-separated. Must contain `openid`. Keep `email`: without a verified email claim the admin can never be linked or bootstrapped. |
| `OIDC_REDIRECT_URL` | `{CLIENT_URL}/api/v1/auth/oidc/callback` | Set it when the API is not served under `CLIENT_URL`. OPs compare it to the registered value as an exact string, so trailing slashes and ports matter. |

`OIDC_ISSUER` and `OIDC_REDIRECT_URL` must be `https` URLs; plain `http` is accepted only for `localhost`, `127.0.0.1` and `::1`. Invalid configuration stops the API server at startup. Discovery happens on the first OIDC login and is retried after a failure, so an OP that is down at boot only makes OIDC logins fail until it is back.

## Registering the client

Both options use the authorization code flow with PKCE S256. An OP whose discovery document does not list `S256` in `code_challenge_methods_supported` is rejected.

### A. Registered client

Works with any OP.

1. Register a client with redirect URI `https://peekaping.example/api/v1/auth/oidc/callback`, either public (PKCE only) or confidential with `client_secret_basic`. Other token endpoint auth methods are not supported.
2. Restrict which users may use the client.
3. Set `OIDC_ISSUER`, `OIDC_CLIENT_ID` and, for a confidential client, `OIDC_CLIENT_SECRET`.

### B. Client ID Metadata Document

For OPs that implement [draft-ietf-oauth-client-id-metadata-document](https://datatracker.ietf.org/doc/draft-ietf-oauth-client-id-metadata-document/) and advertise `client_id_metadata_document_supported` in discovery.

Leave `OIDC_CLIENT_ID` and `OIDC_CLIENT_SECRET` unset. The client ID becomes `OIDC_REDIRECT_URL` with `/callback` replaced by `/client`, and Peekaping serves this document there (`GET /api/v1/auth/oidc/client`, cached for an hour):

```json
{
  "client_id": "https://peekaping.example/api/v1/auth/oidc/client",
  "client_name": "Peekaping",
  "redirect_uris": ["https://peekaping.example/api/v1/auth/oidc/callback"],
  "grant_types": ["authorization_code"],
  "response_types": ["code"],
  "token_endpoint_auth_method": "none",
  "scope": "openid email"
}
```

`OIDC_REDIRECT_URL` must end in `/auth/oidc/callback` so the document URL can be derived. The OP fetches the document, so the API must be reachable from the OP; most OPs also require the URL to be allowlisted.

## Login flow

```
browser ──GET /api/v1/auth/oidc/login──▶ api  (302 to OP /authorize, sets the state cookie)
browser ◀──────── OP login/consent ───────▶ OP
browser ──GET /api/v1/auth/oidc/callback?code&state──▶ api
                                                     api ──code + verifier──▶ OP /token
                                                     api verifies the ID token, maps it to the admin
browser ◀─302 {CLIENT_URL}/login#access_token=…&refresh_token=… ── api
```

- State, nonce and PKCE verifier travel in a signed, HttpOnly, 10-minute cookie (`__Host-oidc_state` over https), so multiple API replicas need no shared state.
- The callback checks the state, the RFC 9207 `iss` parameter when the OP advertises support for it, the ID token signature (asymmetric algorithms only), issuer, audience and nonce. An ID token with several audiences is accepted only if `azp` is the client ID.
- Peekaping then issues its own access and refresh tokens, exactly as for password login. No OP tokens are stored, and refresh, expiry and logout stay local.
- Tokens are returned in the URL fragment, which is never sent to a server or logged. The login page clears it, calls `GET /api/v1/auth/me` with the token, and only then stores the session.
- Peekaping's own 2FA is not applied to OIDC logins; enforce MFA at the OP.
- The callback is covered by the same brute-force protection as password login.

Failures redirect to `/login?error=oidc_not_admin` (the identity is not the admin) or `?error=oidc_failed` (anything else). Details go to the API server log only.

## Identity mapping

The admin is linked to an OIDC identity once and recognized by its subject from then on. The link is stored as `{issuer}|{sub}` in the user's `oidc_subject` column, which is unique and compared byte for byte.

- **Bound:** a user already carries this subject, so that user is logged in. Email is not consulted, so changing or reassigning the address at the OP has no effect.
- **Not yet bound:** email decides, once, which account gets linked. The identity needs an `email` claim with `email_verified` set to `true`, read from the ID token or, if absent there, from the UserInfo endpoint (whose `sub` must match). Then:
  - the admin has that email (case-insensitive) and no linked subject: link it and log in;
  - the admin with that email is linked to a different subject: rejected (`oidc_not_admin`);
  - there are no users yet: create the admin with that email and subject, replacing the registration step on a fresh install;
  - otherwise: rejected (`oidc_not_admin`).

Linking and bootstrapping are atomic in the database, so concurrent first logins cannot produce two linked subjects or two admins.

:::warning
On a fresh install, whoever the OP lets through first becomes the admin. Restrict the client at the OP before the first login.
:::

### Password fallback

An admin created through OIDC has no password, so password login and 2FA setup are unavailable for it. Set a password from the profile page (any value is accepted as the current password while none is set) **before** turning OIDC off; otherwise the only way back in is a fresh database.

### Changing the OP

There is no UI for unlinking. Changing `OIDC_ISSUER` (a new OP, or a new public URL for the same one) leaves the admin bound to the old issuer and refuses the new identity. Clear the admin's `oidc_subject` in the database, and the next OIDC login links again by email.

## Deployment notes

- Bundle images: the defaults work, since `CLIENT_URL` already serves `/api`.
- Separate web and API deployments: set `OIDC_REDIRECT_URL` to the API's public callback URL. In metadata-document mode the client ID follows it and still points at the API.
- The token, JWKS and UserInfo endpoints come from discovery and may be on a different host than the issuer.

## Not supported

- Multiple users, roles or group-to-role mapping.
- Disabling password login.
- RP-initiated logout.
- Configuring the OP from the settings UI.
- Pushed Authorization Requests (RFC 9126).
