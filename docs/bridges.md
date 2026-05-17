# Auth Bridges

`@alyldas/uniauth/bridges` exposes optional helper functions for application auth frameworks.

The bridge helpers do one narrow job: they map framework-owned OAuth callback or account data into a
stable `ProviderIdentityAssertion` that the existing UniAuth service can consume.

They do not add runtime dependencies on Better Auth or Auth.js to the core package.

## Import

```ts
import { mapAuthJsOAuthToAssertion, mapBetterAuthOAuthToAssertion } from '@alyldas/uniauth/bridges'
```

## What the Framework Still Owns

- provider setup and provider SDK/runtime wiring;
- routes, callbacks, middleware, and request lifecycle;
- cookies, session transport, JWT handling, and CSRF state;
- token storage, refresh, rotation, and revocation;
- framework-specific user/account/session tables and plugins.

## What UniAuth Still Owns

- local user and identity records;
- exact `(provider, providerUserId)` matching;
- policy-driven auto-link, explicit link, unlink, and merge decisions;
- local sessions, verifications, audit events, and storage ports.

## Auth.js

Use the bridge helper inside your app-owned Auth.js sign-in or callback flow after Auth.js has
already validated the provider response:

```ts
import { mapAuthJsOAuthToAssertion } from '@alyldas/uniauth/bridges'

const assertion = mapAuthJsOAuthToAssertion({
  providerId: 'google-workspace',
  account: {
    provider: account.provider,
    providerAccountId: account.providerAccountId,
    type: account.type,
  },
  profile: profile
    ? {
        sub: profile.sub,
        id: profile.id,
        name: profile.name,
        email: profile.email,
        email_verified: profile.email_verified,
        phone_number: profile.phone_number,
        phone_number_verified: profile.phone_number_verified,
        preferred_username: profile.preferred_username,
        picture: profile.picture,
        locale: profile.locale,
      }
    : undefined,
  user: user
    ? {
        name: user.name ?? undefined,
        email: user.email ?? undefined,
        image: user.image ?? undefined,
      }
    : undefined,
  trust: {
    level: 'trusted',
    signals: ['workspace-admin'],
  },
  metadata: {
    tenantId,
  },
})

await authService.public.provider.signIn({ assertion })
```

`providerAccountId` is treated as the exact provider identity key. If the profile subject disagrees
with it, the helper rejects the input instead of silently picking one.

If you want a UniAuth provider namespace that differs from the framework provider id, pass
`providerId`. The original framework id is then kept as `metadata.frameworkProviderId`.

`metadata` must be a reduced plain object with application-owned values. Do not pass raw framework
account, profile, token, request, or session objects into the bridge helper.

## Better Auth

Use the bridge helper after your Better Auth integration has already completed provider validation.
The exact hook or middleware entry point is application-owned and depends on your Better Auth setup.

```ts
import { mapBetterAuthOAuthToAssertion } from '@alyldas/uniauth/bridges'

const assertion = mapBetterAuthOAuthToAssertion({
  providerId: 'discord-app',
  account: {
    providerId: account.providerId,
    accountId: account.accountId,
  },
  profile: oauthProfile
    ? {
        id: oauthProfile.id,
        email: oauthProfile.email,
        emailVerified: oauthProfile.emailVerified,
        name: oauthProfile.name,
        image: oauthProfile.image,
      }
    : undefined,
  user: frameworkUser
    ? {
        email: frameworkUser.email,
        emailVerified: frameworkUser.emailVerified,
        name: frameworkUser.name,
        image: frameworkUser.image,
      }
    : undefined,
  metadata: {
    tenantId,
  },
})

await authService.public.provider.signIn({ assertion })
```

The helper accepts either:

- `account.accountId` from the framework-owned provider account record;
- `profile.id` from the validated OAuth profile.

If both are present and disagree, the helper rejects the input.

`metadata` follows the same boundary as Auth.js metadata: pass only a plain object with explicit
application-owned fields, not raw framework or provider SDK objects.

## Security Notes

- The bridge helpers do not copy access tokens, refresh tokens, or ID tokens into UniAuth
  assertion metadata.
- If you need token persistence, keep it in application-owned storage keyed by your own session or
  callback state.
- If you want one stable record shape for that storage, use `createOAuthOidcTokenRecord(...)` from
  `@alyldas/uniauth/providers/oauth-oidc` and bind it to your framework-owned callback state, local
  user id, or local session id. See [Provider token persistence](provider-token-persistence.md).
- UniAuth policy invariants still apply after mapping. A framework callback does not bypass
  `AuthPolicy`, last-identity rules, or exact provider identity matching.
- These helpers are intentionally thin. If your integration needs framework-native session
  replacement, cookie ownership, or provider-specific token lifecycle management, that remains
  outside the UniAuth package boundary.
