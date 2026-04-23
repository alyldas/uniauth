# OAuth / OIDC Providers

UniAuth exposes a small SDK-free contract for OAuth and OIDC provider adapters. The contract maps a
validated provider profile into `ProviderIdentityAssertion` and then delegates account decisions to
the existing `AuthService`, `ProviderRegistry`, and `AuthPolicy` flow.

## Public API

```ts
import {
  createOAuthOidcProvider,
  mapOAuthOidcProfileToAssertion,
  type OAuthOidcClient,
  type OAuthOidcProfile,
} from '@alyldas/uniauth'
```

## Runtime Boundary

Applications own:

- authorization URL creation;
- callback routes;
- state and nonce validation;
- redirect URI policy;
- PKCE verifier storage;
- provider secrets;
- HTTP clients;
- token persistence.

UniAuth owns only the `AuthProvider.finish()` boundary:

1. read the authorization `code` from `FinishInput`;
2. pass code, state, redirect URI, code verifier, and metadata to an app-owned `OAuthOidcClient`;
3. ask the client for a validated provider profile;
4. map the profile into `ProviderIdentityAssertion`;
5. let the existing auth service handle sign-in, linking, sessions, audit, and policy checks.

## Provider Client

```ts
const client: OAuthOidcClient = {
  async exchangeCode(input) {
    return appOAuthClient.exchangeCode({
      code: input.code,
      redirectUri: input.redirectUri,
      codeVerifier: input.codeVerifier,
    })
  },
  async fetchProfile(input) {
    return appOAuthClient.fetchUserInfo(input.tokens)
  },
}
```

The client should return only the token fields needed to fetch the profile. Long-term token storage
belongs to the application and should happen outside UniAuth.
If an application must retain provider tokens, store them behind an application-owned repository and
keep only the local UniAuth session identifier in UniAuth-facing flows.

## Registration

```ts
providerRegistry.register(
  createOAuthOidcProvider({
    providerId: 'example-oauth',
    client,
  }),
)
```

## Sign-In

```ts
await service.signIn({
  provider: 'example-oauth',
  finishInput: {
    code: request.query.code,
    state: request.query.state,
    payload: {
      redirectUri: 'https://app.example/auth/callback',
      codeVerifier: request.session.oauthCodeVerifier,
    },
  },
})
```

The built-in mapper uses `profile.subject` as `providerUserId`, maps verified email and phone claims,
and copies only reduced profile metadata such as issuer, preferred username, picture URL, locale, and
explicit app-provided profile metadata. It does not copy access tokens or ID tokens into assertion
metadata.

Use `mapProfile` when a provider needs a custom subject format or tenant-specific metadata:

```ts
createOAuthOidcProvider({
  providerId: 'tenant-oauth',
  client,
  mapProfile: ({ provider, profile }) => ({
    provider,
    providerUserId: `${profile.issuer}:${profile.subject}`,
  }),
})
```

Providers can also attach normalized trust context for downstream policy checks:

```ts
createOAuthOidcProvider({
  providerId: 'tenant-oauth',
  client,
  mapProfile: ({ provider, profile }) => ({
    provider,
    providerUserId: profile.subject,
    email: profile.email,
    emailVerified: profile.emailVerified,
    trust: {
      level: 'trusted',
      signals: ['oidc-email-verified', 'tenant-allowlist'],
    },
  }),
})
```

## Security Notes

- Validate `state`, `nonce`, redirect URI, and PKCE verifier in application code before or during
  the client exchange.
- Keep provider secrets out of UniAuth configuration objects when possible; load them in the
  application-owned client.
- Do not store access tokens, ID tokens, or refresh tokens in `ProviderIdentityAssertion.metadata`.
- Exact `(provider, providerUserId)` matching still wins. Email, phone, username, and display fields
  are profile hints, not account ownership proof.
- Auto-link remains controlled by `AuthPolicy`; OAuth/OIDC providers do not silently merge users.
- `ProviderIdentityAssertion.trust` can carry app-owned trust signals into `AuthPolicy.canAutoLink`,
  `AuthPolicy.canLinkIdentity`, and `AuthPolicy.canMergeUsers` without exposing provider SDK types.
