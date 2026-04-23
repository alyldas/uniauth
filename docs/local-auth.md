# Local Auth Flows

UniAuth keeps local auth flows headless. Applications own routes, forms, cookies, delivery
providers, queues, password policy, and rate-limit storage.

## OTP

Use the unified OTP API for email and phone sign-in:

```ts
const challenge = await service.startOtpChallenge({
  purpose: VerificationPurpose.SignIn,
  channel: OtpChannel.Email,
  target: 'alice@example.com',
})

const result = await service.finishOtpSignIn({
  verificationId: challenge.verificationId,
  secret: 'code from user input',
  channel: OtpChannel.Email,
})
```

`finishOtpChallenge` remains for non-sign-in verification purposes such as link, re-auth, recovery,
and app-owned custom purposes.

The default OTP generator emits a 6-digit numeric code. Applications can configure a numeric length
from 4 to 8 digits, provide a custom generator, or pass a per-request `secret`. Per-request secrets
win over configured generation. Empty generated secrets are rejected before a verification is
created.

`emailOtpSubject` customizes only the built-in email OTP subject. Full templates, localization,
provider payloads, queues, retry, and dead-letter behavior remain sender-adapter concerns.

## Magic Link

Email magic links are sign-in verifications delivered through `EmailSender`. Core creates and hashes
the secret, then calls your `createLink` function.

```ts
const magic = await service.startEmailMagicLinkSignIn({
  email: 'alice@example.com',
  createLink: ({ verificationId, secret }) =>
    `/auth/magic?verification=${verificationId}&token=${secret}`,
})

await service.finishEmailMagicLinkSignIn({
  verificationId: magic.verificationId,
  secret: 'token from request',
})
```

The application owns route parsing, redirects, cookies, and browser security headers.

## Passwords

Passwords use `CredentialRepo` and `PasswordHasher`. Core does not bundle a password hashing
runtime; production apps should pass a hasher backed by their chosen algorithm, runtime, and
parameters.

```ts
await service.setPassword({
  userId,
  email: 'alice@example.com',
  password: 'password from settings form',
})

await service.signInWithPassword({
  email: 'alice@example.com',
  password: 'password from sign-in form',
})
```

The password sign-in method is also an `AuthIdentity` with provider `password`, so unlink policy and
last-sign-in-method protection stay shared with provider, OTP, and magic-link identities.

Use `changePassword` when the user knows the current password. Use email password recovery when the
user only has a recovery token:

```ts
const recovery = await service.startEmailPasswordRecovery({
  email: 'alice@example.com',
  createLink: ({ verificationId, secret }) =>
    `/auth/recovery?verification=${verificationId}&token=${secret}`,
})

await service.finishEmailPasswordRecovery({
  verificationId: recovery.verificationId,
  secret: 'token from request',
  newPassword: 'new password from reset form',
})
```

Recovery does not create a session. Applications can decide whether a successful reset should be
followed by a separate sign-in.

## Neutral Responses

Public start responses should not reveal whether an account exists. Core keeps start flows focused
on challenge creation/delivery and uses neutral errors for password credential misses, wrong
passwords, disabled users, and inconsistent credential state.

Applications should avoid exposing repository lookups, sender decisions, or rate-limit bucket names
directly in HTTP responses.

## Rate Limits

Wire `RateLimiter` to security-sensitive attempts:

- `RateLimitAction.ProviderSignIn`: provider and provider user id.
- `RateLimitAction.OtpStart`: channel and normalized target.
- `RateLimitAction.OtpFinish`: channel and verification id.
- `RateLimitAction.MagicLinkStart`: email channel and normalized email.
- `RateLimitAction.MagicLinkFinish`: email channel and verification id.
- `RateLimitAction.PasswordSignIn`: email channel and normalized email.
- `RateLimitAction.PasswordRecoveryStart`: email channel and normalized email.
- `RateLimitAction.PasswordRecoveryFinish`: email channel and verification id.

The core port is intentionally storage/backend agnostic. Redis, database counters, edge rate limits,
headers, retry-after formatting, and abuse analytics remain application or adapter concerns.

## Production Boundaries

Current v0.6 local auth hardening does not try to solve every production edge. The production
normalization and delivery orchestration designs are tracked for v0.10 in [Roadmap](roadmap.md).

For storage and security invariants, see [Architecture](architecture.md) and
[Security model](security.md).
