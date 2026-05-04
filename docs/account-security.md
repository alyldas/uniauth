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

For sign-in method screens:

1. load the aggregate view through `authService.getCurrentAccountInspectionSnapshot(...)` or
   `authService.getAccountSecuritySnapshot(userId)`, depending on whether the route is self-service
   or trusted admin/support;
2. present provider ids, statuses, email or phone hints, and credential types;
3. compose mutations through `unlinkCurrentIdentityByToken(...)`,
   `setCurrentAccountPasswordByToken(...)`, `changeCurrentAccountPasswordByToken(...)`, or new
   provider link flows.

Keep the same public security rules:

- do not allow the last active sign-in method to disappear;
- keep public HTTP responses neutral when mutation attempts fail;
- require recent auth where your policy says it is required.

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
- [OTP backend wiring example](../examples/otp-backend/index.ts)
- [Session transport recipes](session-transport.md)
- [Backend integration recipes](backend-recipes.md)
- [Support and admin inspection recipe](support-inspection.md)
