# Provider Token Persistence

UniAuth does not own provider access tokens, refresh tokens, or ID tokens. If an application needs
them after profile fetch, it should keep them in application-owned storage and lifecycle code.

## Public Helper

```ts
import {
  OAuthOidcTokenBindingKind,
  createOAuthOidcTokenRecord,
  type OAuthOidcTokenRecord,
} from '@alyldas/uniauth'
```

`createOAuthOidcTokenRecord(...)` is a narrow helper for normalizing app-owned OAuth/OIDC token
records. It:

- trims provider ids, provider subjects, binding keys, and token strings;
- accepts access tokens, refresh tokens, ID tokens, or any combination of them;
- preserves expiration and scopes in one stable shape;
- rejects blank binding keys, invalid dates, and malformed scope arrays.

It does not write storage, rotate tokens, call revocation endpoints, or attach provider tokens to
UniAuth identities or sessions.

## Recommended Record Shape

```ts
const record = createOAuthOidcTokenRecord({
  provider: 'google-workspace',
  providerUserId: profile.subject,
  binding: {
    kind: OAuthOidcTokenBindingKind.CallbackState,
    value: request.query.state,
  },
  tokens: {
    accessToken: oauthTokens.accessToken,
    refreshToken: oauthTokens.refreshToken,
    idToken: oauthTokens.idToken,
    expiresAt: oauthTokens.expiresAt,
    scopes: oauthTokens.scopes,
  },
  metadata: {
    issuer: profile.issuer,
  },
})

await providerTokenStore.save(record)
```

The binding key is intentionally application-owned. Use whatever lookup matches your transport:

- callback `state`;
- local session id;
- local user id;
- local identity id;
- another application-specific key.

## Rotation Ownership

Refresh token rotation belongs to the application and provider adapter layer, not to UniAuth core.

Recommended pattern:

1. exchange or refresh tokens through the provider client;
2. build the next normalized token record;
3. atomically overwrite the old stored refresh token;
4. if the provider requires explicit revocation of the previous token, call that provider API from
   application code.

Do not try to encode provider-specific rotation semantics into `AuthPolicy`, `AuthService`, or
`ProviderIdentityAssertion`.

## Revocation Ownership

UniAuth local actions do not revoke provider-side tokens for you:

- `revokeSession(...)` only revokes the local UniAuth session;
- `unlink(...)` only updates local identity links;
- `mergeAccounts(...)` only touches local UniAuth records.

If an application disconnects a provider account, it should:

1. revoke provider tokens through the provider API when required;
2. delete or tombstone the app-owned token record;
3. call the relevant UniAuth local action (`unlink`, `revokeSession`, or both).

## Example Rebinding Flow

One common pattern is:

1. persist provider tokens under callback `state` during OAuth/OIDC callback handling;
2. finish UniAuth sign-in and create the local session;
3. rebind the token record from callback `state` to the local session or user id.

The runnable [OAuth / OIDC wiring example](../examples/oauth-oidc/index.ts) shows this pattern with
an app-owned in-memory token store.
