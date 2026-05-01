# Support and Admin Inspection Recipe

Use this document for trusted backend support or admin tooling that needs to inspect one account,
one verification, or one audit timeline without reaching into adapter internals.

UniAuth still does not own operator authorization, HTTP routes, response pagination, or which
fields a support surface is allowed to expose. Keep this recipe server-only and application-owned.

Use [Account security recipes](account-security.md) for end-user account settings, revoke flows,
unlink, and password-management actions. Use this document when a trusted backend operator needs a
read-only inspection surface.

## Trusted Boundary

Before calling any UniAuth read-side method here, the application should already have decided:

- who is allowed to inspect user security state;
- which `userId`, `verificationId`, or audit filter the operator may target;
- which fields can leave the server;
- how inspection access is logged or audited on the application side.

Do not call these flows directly from browsers or mobile clients.

## Base Account Inspection

The preferred starting point is the trusted aggregate inspection helper:

```ts
const inspection = await authService.getAccountInspectionSnapshot({
  userId,
  auditLimit: 50,
})
```

That one call already gives a trusted server-side view of:

- user profile fields that are safe for account-security surfaces;
- linked identities and provider trust hints;
- local credentials without password hashes;
- local sessions without bearer token hashes.
- a bounded local audit timeline without raw audit metadata.

Typical outward shape for a trusted support endpoint:

```ts
return {
  account: {
    user: {
      id: inspection.account.user.id,
      email: inspection.account.user.email ?? null,
      phone: inspection.account.user.phone ?? null,
      displayName: inspection.account.user.displayName ?? null,
      disabledAt: inspection.account.user.disabledAt?.toISOString() ?? null,
    },
    identities: inspection.account.identities.map((identity) => ({
      id: identity.id,
      provider: identity.provider,
      status: identity.status,
      email: identity.email ?? null,
      emailVerified: identity.emailVerified ?? null,
      phone: identity.phone ?? null,
      phoneVerified: identity.phoneVerified ?? null,
      trustLevel: identity.trustLevel ?? null,
    })),
    credentials: inspection.account.credentials.map((credential) => ({
      id: credential.id,
      type: credential.type,
      subject: credential.subject,
      createdAt: credential.createdAt.toISOString(),
      updatedAt: credential.updatedAt.toISOString(),
    })),
    sessions: inspection.account.sessions.map((session) => ({
      id: session.id,
      status: session.status,
      createdAt: session.createdAt.toISOString(),
      expiresAt: session.expiresAt.toISOString(),
      lastSeenAt: session.lastSeenAt?.toISOString() ?? null,
      revokedAt: session.revokedAt?.toISOString() ?? null,
    })),
  },
  auditEvents: inspection.auditEvents.map((event) => ({
    id: event.id,
    type: event.type,
    occurredAt: event.occurredAt.toISOString(),
    userId: event.userId ?? null,
    identityId: event.identityId ?? null,
    sessionId: event.sessionId ?? null,
  })),
}
```

## Narrow Drill-Down Reads

If the operator surface needs one narrower panel instead of the whole snapshot, UniAuth also
exposes the individual read-side calls:

```ts
const user = await authService.getUser(userId)
const sessions = await authService.getUserSessions(userId)
const credentials = await authService.getUserCredentials(userId)
```

Use the aggregate inspection helper as the default. Reach for these narrower reads only when the
surrounding tooling truly needs independent pagination, separate caching, raw audit metadata, or a
reduced payload.

## Audit Timeline Inspection

If the operator surface needs a custom audit filter or explicitly needs raw audit metadata, drop
down to the narrower audit API:

```ts
const auditEvents = await authService.getAuditEvents({
  userId,
  limit: 50,
})
```

Serialize only the operator-facing fields you actually need:

```ts
return auditEvents.map((event) => ({
  id: event.id,
  type: event.type,
  occurredAt: event.occurredAt.toISOString(),
  userId: event.userId ?? null,
  identityId: event.identityId ?? null,
  sessionId: event.sessionId ?? null,
  metadata: event.metadata ?? null,
}))
```

Do not copy secrets, password material, or raw bearer tokens into audit metadata at the application
layer. Keep the raw audit timeline trusted-backend only, and prefer the aggregate inspection helper
when you do not need metadata.

## Verification Inspection

When support or admin tooling needs to inspect one verification by id:

```ts
const verification = await authService.getVerification(verificationId)
const verificationStatus = toVerificationStatusView(verification)
```

Typical outward shape:

```ts
return {
  id: verificationStatus.id,
  purpose: verificationStatus.purpose,
  status: verificationStatus.status,
  expiresAt: verificationStatus.expiresAt.toISOString(),
  consumedAt: verificationStatus.consumedAt?.toISOString() ?? null,
}
```

Do not expose `secretHash`, raw OTP values, magic-link secrets, or internal routing assumptions to
operator clients.

## Combined Inspection Service

One practical server-side composition pattern is to build one trusted service function and let the
framework layer own authorization and HTTP response shaping:

```ts
async function inspectAccountSecurity(input: {
  readonly userId: string
  readonly verificationId?: string
}) {
  const inspection = await authService.getAccountInspectionSnapshot({
    userId: input.userId,
    auditLimit: 50,
  })

  const verificationStatus = input.verificationId
    ? toVerificationStatusView(await authService.getVerification(input.verificationId))
    : undefined

  return {
    inspection,
    verificationStatus,
  }
}
```

Keep outward serialization and operator authorization outside this helper. UniAuth only owns the
local account-security state, audit timeline composition, and verification lifecycle.

## Action Handoff

Support tooling often needs read-only inspection first and a privileged follow-up action second. Do
not hide that distinction.

Recommended split:

1. inspect through the read-side methods in this document;
2. decide in the application whether the operator may trigger a privileged action;
3. run the actual revoke, unlink, or password-management flow through the service methods described
   in [Account security recipes](account-security.md).

This keeps inspection and mutation authorization explicit instead of coupling support reads to
write-side power.

## Related Documents

- [Account security recipes](account-security.md)
- [Session transport recipes](session-transport.md)
- [Backend integration recipes](backend-recipes.md)
- [Security model](security.md)
