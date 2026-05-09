# Account Security Recipes

Use the public read-side API when you need account-security pages such as:

- sign-in method management;
- current-device and other-device session lists;
- sign-out-current-device or sign-out-other-devices flows;
- trusted security timeline or audit-event inspection;
- support-only verification inspection by id.

UniAuth still does not own HTTP routes, UI, cookies, or client payload shaping. The application
must decide what to expose and must not leak server-only fields such as `passwordHash`,
`tokenHash`, or `secretHash`.

This document starts after transport resolution. Use [Session transport recipes](session-transport.md)
to turn cookies or bearer headers into a trusted local session and `userId`. Use
[Backend integration recipes](backend-recipes.md) for framework-specific bootstrap and route
composition.

Prefer the built-in read-side and projection helpers for these flows:

```ts
const snapshot = await authService.getAccountSecuritySnapshot(userId)

const verificationStatus = toVerificationStatusView(verification)
```

When the caller is already authenticated by a trusted local session token, prefer the aggregate
helper instead of manually composing `resolveSessionContext(...)` with a second user-scoped read:

```ts
const current = await authService.getCurrentAccountInspectionSnapshot({
  sessionToken,
  touch: true,
  audit: {
    limit: 20,
  },
})
```

For pre-closure export screens, use the dedicated closure export snapshot instead of serializing raw
entities or calling storage repositories directly:

```ts
const exportSnapshot = await authService.getCurrentAccountClosureExportSnapshot({
  sessionToken,
  touch: true,
  audit: {
    limit: 50,
  },
})
```

## Recommended Read-Side Shape

The minimal current-account server-side composition usually looks like this:

```ts
const current = await authService.getCurrentAccountInspectionSnapshot({
  sessionToken,
  touch: true,
  audit: {
    limit: 20,
  },
})
```

Keep the response client-safe:

```ts
return {
  user: {
    id: current.account.user.id,
    email: current.account.user.email ?? null,
    displayName: current.account.user.displayName ?? null,
  },
  currentSessionId: current.currentSessionId,
  identities: current.account.identities.map((identity) => ({
    id: identity.id,
    provider: identity.provider,
    status: identity.status,
    email: identity.email ?? null,
    phone: identity.phone ?? null,
    trustLevel: identity.trustLevel ?? null,
  })),
  credentials: current.account.credentials.map((credential) => ({
    id: credential.id,
    type: credential.type,
    subject: credential.subject,
    createdAt: credential.createdAt.toISOString(),
    updatedAt: credential.updatedAt.toISOString(),
  })),
  sessions: current.account.sessions.map((session) => ({
    id: session.id,
    status: session.status,
    isCurrent: session.id === current.currentSessionId,
    createdAt: session.createdAt.toISOString(),
    expiresAt: session.expiresAt.toISOString(),
    lastSeenAt: session.lastSeenAt?.toISOString() ?? null,
    revokedAt: session.revokedAt?.toISOString() ?? null,
  })),
  auditEvents: current.auditEvents.map((event) => ({
    id: event.id,
    type: event.type,
    occurredAt: event.occurredAt.toISOString(),
  })),
  nextAuditCursor: current.nextAuditCursor ?? null,
}
```

Do not serialize:

- `Credential.passwordHash`
- `Session.tokenHash`
- `Verification.secretHash`

The closure export helper returns the same safe account, session, credential, identity, and audit
views plus `generatedAt`. It is intentionally not a legal data-portability export engine. File
format, retention policy, profile data outside local auth, billing state, and downstream
application records remain application-owned.

## Security Timeline

For self-service security timelines backed by a trusted local session token:

```ts
const page = await authService.getCurrentAccountAuditEventPage({
  sessionToken,
  limit: 20,
})
```

For trusted backend security timelines or support inspection:

```ts
const page = await authService.getAuditEventPage({
  userId,
  limit: 20,
})

const events = page.events
```

The service returns local `AuditEvent` records newest-first. Keep outward serialization
application-owned and expose only the fields your support or admin surface actually needs.

For continuation-based current-account pagination, keep the cursor application-owned and derive it
from the last event you already returned:

```ts
const firstPage = await authService.getCurrentAccountAuditEventPage({
  sessionToken,
  limit: 20,
})

const nextPage = await authService.getCurrentAccountAuditEventPage({
  sessionToken,
  before: firstPage.nextCursor,
  limit: 20,
})
```

Trusted backend or support inspection can use the same pagination semantics through the user-scoped
helper:

```ts
const firstPage = await authService.getAuditEventPage({
  userId,
  limit: 20,
})

const nextPage = await authService.getAuditEventPage({
  userId,
  before: firstPage.nextCursor,
  limit: 20,
})
```

Typical server-safe outward shape:

```ts
return events.map((event) => ({
  id: event.id,
  type: event.type,
  occurredAt: event.occurredAt.toISOString(),
  userId: event.userId ?? null,
  identityId: event.identityId ?? null,
  sessionId: event.sessionId ?? null,
  metadata: event.metadata ?? null,
}))
```

Do not add secrets or credential material to audit metadata in application code. Keep the same
trusted-backend assumption here as for verification inspection.

For a larger trusted support or admin inspection surface that combines snapshot, audit, and
verification reads, continue in [Support and admin inspection recipe](support-inspection.md).

## Session Action Recipes

For device-list or active-session screens:

1. resolve or trust the current local session token from the transport;
2. load the aggregate view through `authService.getCurrentAccountSecuritySnapshot(...)`;
3. present a sanitized session list;
4. keep revoke and logout responses application-owned.

### Current Device Logout

Treat sign-out of the current device as one backend write plus one transport cleanup:

```ts
await authService.revokeCurrentSessionByToken({
  sessionToken: request.auth.sessionToken,
})
clearSessionCookie(response)
```

UniAuth changes only the local session record. The application still owns cookie clearing, bearer
token deletion, mobile secure-storage deletion, redirect behavior, and neutral response payloads.

### Sign Out Other Devices

For "sign out other devices" or "sign out all devices except this one":

```ts
const result = await authService.revokeOtherSessionsByToken({
  sessionToken: request.auth.sessionToken,
})

return {
  currentSessionId: result.currentSessionId,
  revokedSessionCount: result.revokedSessionIds.length,
}
```

This is the narrowest server-side flow when the caller is already authenticated and the target user
is the current account. It keeps the current transport alive while revoking the other local session
records and returns the current session id the application can mark in its response.

### Revoke One Selected Device

For per-device revoke actions, keep the mutation on the trusted current-account boundary and let the
service enforce ownership of the selected session:

```ts
const result = await authService.revokeOwnedSessionByToken({
  sessionToken: request.auth.sessionToken,
  targetSessionId: body.sessionId,
})

if (result.revokedCurrentSession) {
  clearSessionCookie(response)
}

return response.status(204).send()
```

The application can still pre-load the session list through
`getCurrentAccountSecuritySnapshot(...)` for UI rendering, but the write-side route no longer has to
re-prove ownership by hand. Missing, foreign, stale, or disabled-account session targets collapse
to the neutral `SessionNotFound` path.

## Sign-In Method Action Recipes

### Update Current Account Profile

Use `updateCurrentAccountProfileByToken(...)` when an authenticated settings route needs to update
local auth profile fields owned by the `User` record:

```ts
const user = await authService.updateCurrentAccountProfileByToken({
  sessionToken: request.auth.sessionToken,
  displayName: body.displayName,
  reAuthenticatedAt: request.auth.reAuthenticatedAt,
})

return {
  id: user.id,
  displayName: user.displayName ?? null,
  updatedAt: user.updatedAt.toISOString(),
}
```

The helper trims display names and treats a blank display name as clearing the local display name.
It does not update email, phone, identities, credentials, avatars, media storage, or product profile
tables. Keep those flows application-owned or route them through identity linking, unlinking, and
verification flows where ownership can be proven.

Applications that consider profile changes sensitive can configure
`AuthPolicyAction.UpdateProfile` in `requireReAuthFor` and pass the same app-owned
`reAuthenticatedAt` marker used by password, unlink, and closure routes.

### Update Current Account Contact

Use `startCurrentAccountContactChange(...)` and `finishCurrentAccountContactChange(...)` when an
authenticated settings route needs to update the local `User.email` or `User.phone` field after OTP
proof on the new target:

```ts
const started = await authService.startCurrentAccountContactChange({
  sessionToken: request.auth.sessionToken,
  channel: body.channel,
  target: body.target,
  reAuthenticatedAt: request.auth.reAuthenticatedAt,
})

return {
  verificationId: started.verificationId,
  expiresAt: started.expiresAt.toISOString(),
  delivery: started.delivery,
}
```

```ts
const user = await authService.finishCurrentAccountContactChange({
  sessionToken: request.auth.sessionToken,
  verificationId: body.verificationId,
  secret: body.code,
})

return {
  id: user.id,
  email: user.email ?? null,
  phone: user.phone ?? null,
  updatedAt: user.updatedAt.toISOString(),
}
```

`resendCurrentAccountContactChange(...)` and `cancelCurrentAccountContactChange(...)` keep the
challenge on the same trusted `sessionToken` boundary. The helpers normalize email and phone
targets, reject unchanged targets, and update only the local `User` contact field after successful
verification. They do not rewrite sign-in identities, password credential subjects, OAuth provider
profiles, notification preferences, or product profile tables.

Applications that consider contact changes sensitive can configure `AuthPolicyAction.UpdateContact`
in `requireReAuthFor` and pass the same app-owned `reAuthenticatedAt` marker used by password,
unlink, profile, and closure routes.

For sign-in method screens:

1. load the aggregate view through `authService.getCurrentAccountInspectionSnapshot(...)` or
   `authService.getAccountSecuritySnapshot(userId)`, depending on whether the route is self-service
   or trusted admin/support;
2. present provider ids, statuses, email or phone hints, and credential types;
3. compose mutations through `linkCurrentIdentityByToken(...)`, `unlinkCurrentIdentityByToken(...)`,
   `setCurrentAccountPasswordByToken(...)`, `changeCurrentAccountPasswordByToken(...)`,
   `startCurrentAccountContactChange(...)`, `finishCurrentAccountContactChange(...)`,
   `closeCurrentAccountByToken(...)`, or new provider link flows.

Keep the same public security rules:

- do not allow the last active sign-in method to disappear;
- keep public HTTP responses neutral when mutation attempts fail;
- require recent auth where your policy says it is required.

### Bootstrap Recent Auth For Sensitive Current-Account Actions

Keep recent-auth proof on the same trusted `sessionToken` boundary as the current-account
inspection and write-side helpers. UniAuth can prove the owned current-account factor; the
application still owns where the resulting recent-auth marker is stored and how long it remains
valid.

For owned OTP re-auth, let the route select an identity from the current-account snapshot and keep
the ownership check inside core:

```ts
const challenge = await authService.startCurrentAccountOtpReAuth({
  sessionToken: request.auth.sessionToken,
  identityId: body.identityId,
  channel: body.channel,
})
```

Then finish the challenge through the existing generic verification consumer and persist the recent
auth marker in app-owned request or session state:

```ts
const verification = await authService.finishOtpChallenge({
  verificationId: body.verificationId,
  secret: body.secret,
  purpose: VerificationPurpose.ReAuth,
  channel: body.channel,
})

request.auth.reAuthenticatedAt = verification.consumedAt ?? new Date()
```

If the UI prefers password confirmation instead of OTP, keep that proof on the same trusted local
session boundary:

```ts
const confirmation = await authService.confirmCurrentAccountPasswordByToken({
  sessionToken: request.auth.sessionToken,
  currentPassword: body.currentPassword,
})

request.auth.reAuthenticatedAt = confirmation.reAuthenticatedAt
```

If the route only needs to render whether a fresh recent-auth step is still required, keep that
check on the same trusted current-account boundary too:

```ts
const status = await authService.getCurrentAccountReAuthStatus({
  sessionToken: request.auth.sessionToken,
  action: AuthPolicyAction.ChangePassword,
  reAuthenticatedAt: request.auth.reAuthenticatedAt,
})
```

If the route must actively enforce recent-auth before additional app-owned side effects, prefer the
assert helper over duplicating policy checks in application code:

```ts
await authService.assertCurrentAccountReAuth({
  sessionToken: request.auth.sessionToken,
  action: AuthPolicyAction.ChangePassword,
  reAuthenticatedAt: request.auth.reAuthenticatedAt,
})
```

UniAuth still does not own:

- your recent-auth cookie or session storage;
- the TTL of that marker in app-owned auth state;
- browser redirect or challenge-step UI;
- whether the route offers OTP, password confirmation, or both.

For resend or cancellation after a current-account OTP re-auth challenge has started, keep that
management on the same trusted `sessionToken` boundary too. The route can stay inside
current-account ownership checks instead of falling back to generic verification orchestration:

```ts
const resent = await authService.resendCurrentAccountOtpReAuth({
  sessionToken: request.auth.sessionToken,
  verificationId: body.verificationId,
})

await authService.cancelCurrentAccountOtpReAuth({
  sessionToken: request.auth.sessionToken,
  verificationId: body.verificationId,
})
```

The application still owns UI cooldown timers, retry buttons, and how the new `verificationId`
replaces the previous one in client state after a resend.

### Link A New Sign-In Method

Keep self-service linking on the same trusted `sessionToken` boundary as the rest of the
current-account write-side surface. The route should still resolve assertion input or provider
finish payloads in application code, but it should not fall back to raw `userId` orchestration
once the caller is already authenticated.

For direct assertion linking:

```ts
const result = await authService.linkCurrentIdentityByToken({
  sessionToken: request.auth.sessionToken,
  assertion: {
    provider: 'github',
    providerUserId: body.providerUserId,
    email: body.email,
    emailVerified: body.emailVerified,
    displayName: body.displayName,
  },
  reAuthenticatedAt: request.auth.reAuthenticatedAt,
})

return {
  identityId: result.identity.id,
  linked: result.linked,
}
```

For provider-finish flows such as OAuth/OIDC or messenger adapters, keep the same trusted boundary
and pass the finish payload through the helper instead of resolving the current account first and
then calling raw `link(...)`:

```ts
const result = await authService.linkCurrentIdentityByToken({
  sessionToken: request.auth.sessionToken,
  provider: 'oidc',
  finishInput: {
    payload: request.body,
  },
  reAuthenticatedAt: request.auth.reAuthenticatedAt,
})

return {
  identityId: result.identity.id,
  linked: result.linked,
}
```

This keeps the same core semantics as `link(...)`:

- exact already-linked identities still win before policy or looser matching logic;
- same-user relinks stay idempotent through `linked: false`;
- stale or disabled current-account state collapses to the neutral `SessionNotFound` path on the
  trusted session boundary;
- policy-denied and already-linked failures still use the existing public error codes.

### Unlink One Sign-In Method

Resolve the current account snapshot first so the application knows which method the user selected,
then keep the unlink on the current-account token boundary:

```ts
await authService.unlinkCurrentIdentityByToken({
  sessionToken: request.auth.sessionToken,
  identityId: body.identityId,
  reAuthenticatedAt: request.auth.reAuthenticatedAt,
})

return response.status(204).send()
```

If policy or invariant checks reject the unlink, keep the outward response neutral enough for your
surface. Core still protects the last remaining active sign-in method and now also keeps foreign or
stale identity targets on the same trusted current-account boundary.

### Add Or Replace A Local Password

Use `setCurrentAccountPasswordByToken(...)` when the account does not yet have a local password or
when the application allows a provider-first account to add one from a trusted account-security
screen:

```ts
await authService.setCurrentAccountPasswordByToken({
  sessionToken: request.auth.sessionToken,
  password: body.newPassword,
  reAuthenticatedAt: request.auth.reAuthenticatedAt,
})
```

The application still owns password policy UX, strength hints, recent-auth requirements, and
whether the route should even be offered when a password credential already exists.
`setCurrentAccountPasswordByToken(...)` only works when the current account already has a trusted
email address. If not, core rejects the route with `invalid_input` instead of letting the
application invent a local password identity subject.

### Change Password

Use `changeCurrentAccountPasswordByToken(...)` when the current user already knows the existing
password:

```ts
await authService.changeCurrentAccountPasswordByToken({
  sessionToken: request.auth.sessionToken,
  currentPassword: body.currentPassword,
  newPassword: body.newPassword,
  reAuthenticatedAt: request.auth.reAuthenticatedAt,
})
```

Keep incorrect current-password responses neutral and leave session refresh, cookie rotation, or
"sign out other devices after password change" policy in the application layer.

### Close Current Account

If the account-closure flow offers a "download my auth security data" step, keep that route
read-only and on the same trusted session boundary:

```ts
const exportSnapshot = await authService.getCurrentAccountClosureExportSnapshot({
  sessionToken: request.auth.sessionToken,
  audit: {
    limit: 50,
  },
})

return {
  generatedAt: exportSnapshot.generatedAt.toISOString(),
  user: exportSnapshot.account.user,
  identities: exportSnapshot.account.identities,
  credentials: exportSnapshot.account.credentials,
  sessions: exportSnapshot.account.sessions,
  auditEvents: exportSnapshot.auditEvents,
  nextAuditCursor: exportSnapshot.nextAuditCursor ?? null,
}
```

Keep the actual download format application-owned. The helper only returns local auth safe views;
it does not collect product profile data, billing records, provider token records, or downstream
application tables.

Use `closeCurrentAccountByToken(...)` for self-service account closure from an authenticated
settings route. Keep the recent-auth marker application-owned, then pass it into the helper on the
same trusted current-account boundary:

```ts
const result = await authService.closeCurrentAccountByToken({
  sessionToken: request.auth.sessionToken,
  reAuthenticatedAt: request.auth.reAuthenticatedAt,
})

clearSessionCookie(response)

return response.status(204).send({
  currentSessionId: result.currentSessionId,
  revokedSessionIds: result.revokedSessionIds,
})
```

Core disables the current user record and revokes that user's active local sessions, including the
current session. Stale, expired, revoked, or disabled current-account contexts collapse to the
neutral `SessionNotFound` path before any account state changes happen.

UniAuth still does not own browser cookie clearing, legal retention, data export, profile
anonymization, billing cancellation, or downstream application data deletion. Run those as
application-owned side effects after the helper succeeds.

### Password Recovery Handoff

If the user cannot prove the current password, hand off from the authenticated or unauthenticated
surface into the shared email recovery flow:

```ts
const recovery = await authService.startEmailPasswordRecovery({
  email: body.email,
  createLink(input) {
    return `https://example.com/auth/recovery?verification=${input.verificationId}&token=${input.secret}`
  },
})
```

Then finish it from the recovery route:

```ts
await authService.finishEmailPasswordRecovery({
  verificationId: body.verificationId,
  secret: body.secret,
  newPassword: body.newPassword,
})
```

UniAuth keeps the verification lifecycle and hashed secret storage. The application still owns the
delivery channel, the recovery URL, browser redirect choices, and whether recovery completion also
creates or rotates a local session.

## Verification Inspection

UniAuth now exposes:

```ts
const verification = await authService.getVerification(verificationId)
const verificationStatus = toVerificationStatusView(verification)
```

Use it for:

- polling one OTP or magic-link challenge from a trusted backend;
- support tooling that needs to inspect whether a verification is still pending, consumed, or
  expired;
- server-side orchestration that needs `purpose`, `status`, and `expiresAt`.

When exposing this outward, serialize only safe fields:

```ts
return {
  id: verificationStatus.id,
  purpose: verificationStatus.purpose,
  status: verificationStatus.status,
  expiresAt: verificationStatus.expiresAt.toISOString(),
  consumedAt: verificationStatus.consumedAt?.toISOString() ?? null,
}
```

Do not send `secretHash` to browsers, mobile clients, or untrusted callers.

## Example References

- [Express auth module example](../examples/express-auth/index.ts)
- [Fastify auth module example](../examples/fastify-auth/index.ts)
- [Current-account contact change example](../examples/current-account-contact-change/index.ts)
- [OTP backend wiring example](../examples/otp-backend/index.ts)
- [Session transport recipes](session-transport.md)
- [Backend integration recipes](backend-recipes.md)
- [Support and admin inspection recipe](support-inspection.md)
