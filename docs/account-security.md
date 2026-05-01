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

## Recommended Read-Side Shape

The minimal server-side composition usually looks like this:

```ts
const snapshot = await authService.getAccountSecuritySnapshot(userId)
```

Keep the response client-safe:

```ts
return {
  user: {
    id: snapshot.user.id,
    email: snapshot.user.email ?? null,
    displayName: snapshot.user.displayName ?? null,
  },
  identities: snapshot.identities.map((identity) => ({
    id: identity.id,
    provider: identity.provider,
    status: identity.status,
    email: identity.email ?? null,
    phone: identity.phone ?? null,
    trustLevel: identity.trustLevel ?? null,
  })),
  credentials: snapshot.credentials.map((credential) => ({
    id: credential.id,
    type: credential.type,
    subject: credential.subject,
    createdAt: credential.createdAt.toISOString(),
    updatedAt: credential.updatedAt.toISOString(),
  })),
  sessions: snapshot.sessions.map((session) => ({
    id: session.id,
    status: session.status,
    createdAt: session.createdAt.toISOString(),
    expiresAt: session.expiresAt.toISOString(),
    lastSeenAt: session.lastSeenAt?.toISOString() ?? null,
    revokedAt: session.revokedAt?.toISOString() ?? null,
  })),
}
```

Do not serialize:

- `Credential.passwordHash`
- `Session.tokenHash`
- `Verification.secretHash`

## Security Timeline

For trusted backend security timelines or support inspection:

```ts
const events = await authService.getAuditEvents({
  userId,
  limit: 20,
})
```

The service returns local `AuditEvent` records newest-first. Keep outward serialization
application-owned and expose only the fields your support or admin surface actually needs.

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

## Device Management

For device-list or active-session screens:

1. resolve the current local session from the transport;
2. load the aggregate view through `authService.getAccountSecuritySnapshot(userId)`;
3. present a sanitized session list;
4. revoke one or many sessions through:
   - `authService.revokeSession(sessionId)`
   - `authService.revokeUserSessions({ userId, exceptSessionId })`

The application still owns cookie clearing, mobile token deletion, and client refresh behavior
after a revoke.

## Sign-In Method Management

For sign-in method screens:

1. load the aggregate view through `authService.getAccountSecuritySnapshot(userId)`;
2. present provider ids, statuses, email or phone hints, and credential types;
3. use `unlink(...)`, `setPassword(...)`, `changePassword(...)`, or new provider link flows for
   mutations.

Keep the same public security rules:

- do not allow the last active sign-in method to disappear;
- keep public HTTP responses neutral when mutation attempts fail;
- require recent auth where your policy says it is required.

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
