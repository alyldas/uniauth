import { describe, expect, it } from 'vitest'
import {
  AuditEventType,
  PASSWORD_PROVIDER_ID,
  SessionStatus,
  UniAuthErrorCode,
  VerificationPurpose,
  addSeconds,
  createDefaultAuthPolicy,
} from '../../src'
import { createPostgresTestKit, now } from './support.js'

describe('Postgres reference persistence security and read side', () => {
  it('keeps exact provider identity ahead of profile attributes on Postgres', async () => {
    const { service, store } = await createPostgresTestKit()

    const first = await service.signIn({
      assertion: {
        provider: 'oidc',
        providerUserId: 'pg-exact-user',
        email: 'first@example.com',
        emailVerified: true,
      },
      now,
    })
    const second = await service.signIn({
      assertion: {
        provider: 'oidc',
        providerUserId: 'pg-exact-user',
        email: 'different@example.com',
        emailVerified: true,
      },
      now,
    })

    expect(second.isNewUser).toBe(false)
    expect(second.isNewIdentity).toBe(false)
    expect(second.user.id).toBe(first.user.id)
    expect(await store.userRepo.findById(first.user.id)).toMatchObject({
      id: first.user.id,
    })
    expect(await store.identityRepo.listByUserId(first.user.id)).toHaveLength(1)
    expect(await store.sessionRepo.listByUserId(first.user.id)).toHaveLength(2)
  })

  it('does not silently auto-merge verified email identities on Postgres under the default policy', async () => {
    const { service, store } = await createPostgresTestKit({
      policy: createDefaultAuthPolicy(),
    })

    const emailUser = await service.signIn({
      assertion: {
        provider: 'email',
        providerUserId: 'pg-email-user',
        email: 'shared@example.com',
        emailVerified: true,
      },
      now,
    })
    const oauthUser = await service.signIn({
      assertion: {
        provider: 'oidc',
        providerUserId: 'pg-oauth-user',
        email: 'shared@example.com',
        emailVerified: true,
      },
      now,
    })

    expect(oauthUser.isNewUser).toBe(true)
    expect(oauthUser.user.id).not.toBe(emailUser.user.id)
    expect(await store.userRepo.findById(emailUser.user.id)).toMatchObject({
      id: emailUser.user.id,
    })
    expect(await store.userRepo.findById(oauthUser.user.id)).toMatchObject({
      id: oauthUser.user.id,
    })
  })

  it('rejects unlinking the last active identity on Postgres', async () => {
    const { service } = await createPostgresTestKit({
      policy: createDefaultAuthPolicy(),
    })
    const signedIn = await service.signIn({
      assertion: {
        provider: 'email',
        providerUserId: 'pg-last-identity',
        email: 'last@example.com',
        emailVerified: true,
      },
      now,
    })

    await expect(
      service.unlink({
        userId: signedIn.user.id,
        identityId: signedIn.identity.id,
        now,
      }),
    ).rejects.toMatchObject({
      code: UniAuthErrorCode.LastIdentity,
    })
  })

  it('keeps invalid password sign-in responses neutral on Postgres', async () => {
    const { service, store } = await createPostgresTestKit()
    const signedIn = await service.signIn({
      assertion: {
        provider: 'email',
        providerUserId: 'pg-neutral-password',
        email: 'neutral@example.com',
        emailVerified: true,
      },
      now,
    })

    await service.setPassword({
      userId: signedIn.user.id,
      email: 'neutral@example.com',
      password: 'correct-secret',
      now,
    })

    await expect(
      service.signInWithPassword({
        email: 'missing@example.com',
        password: 'wrong-secret',
        now,
      }),
    ).rejects.toMatchObject({
      code: UniAuthErrorCode.InvalidCredentials,
      message: 'Email or password is invalid.',
    })
    await expect(
      service.signInWithPassword({
        email: 'neutral@example.com',
        password: 'wrong-secret',
        now,
      }),
    ).rejects.toMatchObject({
      code: UniAuthErrorCode.InvalidCredentials,
      message: 'Email or password is invalid.',
    })

    expect(await store.sessionRepo.listByUserId(signedIn.user.id)).toHaveLength(1)
  })

  it('touches active sessions on Postgres without rewinding last seen activity', async () => {
    const { service } = await createPostgresTestKit()
    const signedIn = await service.signIn({
      assertion: {
        provider: 'email',
        providerUserId: 'pg-touch-session',
        email: 'pg-touch-session@example.com',
        emailVerified: true,
      },
      now,
    })
    const touchedAt = addSeconds(now, 60)
    const touched = await service.touchSession({
      sessionId: signedIn.session.id,
      now: touchedAt,
    })

    expect(touched.lastSeenAt).toEqual(touchedAt)
    expect(
      await service.touchSession({
        sessionId: signedIn.session.id,
        now: addSeconds(now, 30),
      }),
    ).toMatchObject({
      id: signedIn.session.id,
      lastSeenAt: touchedAt,
    })
  })

  it('lists local sessions for an active user on Postgres', async () => {
    const { service } = await createPostgresTestKit()
    const first = await service.signIn({
      assertion: {
        provider: 'email',
        providerUserId: 'pg-list-sessions',
        email: 'pg-list-sessions@example.com',
        emailVerified: true,
      },
      now,
    })
    const second = await service.createSession({
      userId: first.user.id,
      now: addSeconds(now, 10),
      metadata: { createdBy: 'test' },
    })

    expect((await service.getUserSessions(first.user.id)).map((session) => session.id)).toEqual([
      first.session.id,
      second.session.id,
    ])
    expect(await service.getUser(first.user.id)).toMatchObject({
      id: first.user.id,
      email: 'pg-list-sessions@example.com',
    })
  })

  it('reads credentials and verifications through the public service surface on Postgres', async () => {
    const { service } = await createPostgresTestKit()
    const signedIn = await service.signIn({
      assertion: {
        provider: 'email',
        providerUserId: 'pg-read-side-credential',
        email: 'pg-read-side-credential@example.com',
        emailVerified: true,
      },
      now,
    })
    const credential = await service.setPassword({
      userId: signedIn.user.id,
      email: 'pg-read-side-credential@example.com',
      password: 'pg-password',
      now: addSeconds(now, 1),
    })
    const createdVerification = await service.createVerification({
      purpose: VerificationPurpose.SignIn,
      target: 'pg-read-side-credential@example.com',
      secret: '654321',
      now: addSeconds(now, 2),
    })

    expect(await service.getUserCredentials(signedIn.user.id)).toEqual([credential])
    expect(await service.getVerification(createdVerification.verification.id)).toEqual(
      createdVerification.verification,
    )
    expect(await service.getAccountSecuritySnapshot(signedIn.user.id)).toEqual({
      user: {
        id: signedIn.user.id,
        email: 'pg-read-side-credential@example.com',
        createdAt: signedIn.user.createdAt,
        updatedAt: signedIn.user.updatedAt,
      },
      identities: [
        {
          id: signedIn.identity.id,
          provider: signedIn.identity.provider,
          status: signedIn.identity.status,
          email: 'pg-read-side-credential@example.com',
          emailVerified: true,
          createdAt: signedIn.identity.createdAt,
          updatedAt: signedIn.identity.updatedAt,
        },
        {
          provider: PASSWORD_PROVIDER_ID,
          status: 'active',
          email: 'pg-read-side-credential@example.com',
          emailVerified: true,
          id: expect.any(String),
          createdAt: credential.createdAt,
          updatedAt: credential.updatedAt,
        },
      ],
      credentials: [
        {
          id: credential.id,
          type: credential.type,
          subject: credential.subject,
          createdAt: credential.createdAt,
          updatedAt: credential.updatedAt,
        },
      ],
      sessions: [
        {
          id: signedIn.session.id,
          status: signedIn.session.status,
          createdAt: signedIn.session.createdAt,
          expiresAt: signedIn.session.expiresAt,
        },
      ],
    })
  })

  it('reads audit events through the public service surface on Postgres', async () => {
    const { service, store } = await createPostgresTestKit()
    const signedIn = await service.signIn({
      assertion: {
        provider: 'email',
        providerUserId: 'pg-audit-reader',
        email: 'pg-audit-reader@example.com',
        emailVerified: true,
      },
      now,
    })

    await service.createVerification({
      purpose: VerificationPurpose.SignIn,
      target: 'pg-audit-reader@example.com',
      secret: '654321',
      now: addSeconds(now, 5),
    })
    await service.revokeSession(signedIn.session.id)

    expect((await service.getAuditEvents()).map((event) => event.type)).toEqual([
      AuditEventType.SessionRevoked,
      AuditEventType.VerificationCreated,
      AuditEventType.SignIn,
      AuditEventType.SessionCreated,
    ])
    expect(
      (
        await service.getAuditEvents({
          userId: signedIn.user.id,
          limit: 3,
        })
      ).map((event) => event.type),
    ).toEqual([AuditEventType.SessionRevoked, AuditEventType.SignIn, AuditEventType.SessionCreated])
    expect(
      (
        await service.getAuditEvents({
          sessionId: signedIn.session.id,
          limit: 2,
        })
      ).map((event) => event.type),
    ).toEqual([AuditEventType.SessionRevoked, AuditEventType.SignIn])
    expect(
      (
        await service.getAuditEvents({
          identityId: signedIn.identity.id,
          type: AuditEventType.SignIn,
          before: addSeconds(now, 1),
          limit: 5,
        })
      ).map((event) => event.type),
    ).toEqual([AuditEventType.SignIn])
    expect(
      (
        await store.auditLogRepo.list({
          identityId: signedIn.identity.id,
          type: AuditEventType.SignIn,
        })
      ).map((event) => event.type),
    ).toEqual([AuditEventType.SignIn])
  })

  it('bulk-revokes active user sessions on Postgres while keeping the excluded session', async () => {
    const { service, store } = await createPostgresTestKit()
    const first = await service.signIn({
      assertion: {
        provider: 'email',
        providerUserId: 'pg-bulk-revoke',
        email: 'pg-bulk-revoke@example.com',
        emailVerified: true,
      },
      now,
    })
    const second = await service.createSession({
      userId: first.user.id,
      now: addSeconds(now, 10),
    })
    const third = await service.createSession({
      userId: first.user.id,
      now: addSeconds(now, 20),
    })

    const result = await service.revokeUserSessions({
      userId: first.user.id,
      exceptSessionId: first.session.id,
      now: addSeconds(now, 30),
    })

    expect(result).toEqual({
      userId: first.user.id,
      revokedSessionIds: [second.session.id, third.session.id],
    })
    expect(await service.getUserSessions(first.user.id)).toMatchObject([
      { id: first.session.id, status: SessionStatus.Active },
      { id: second.session.id, status: SessionStatus.Revoked },
      { id: third.session.id, status: SessionStatus.Revoked },
    ])
    await store.userRepo.update(first.user.id, { disabledAt: addSeconds(now, 40) })
    await expect(service.getUser(first.user.id)).rejects.toMatchObject({
      code: UniAuthErrorCode.UserNotFound,
    })
  })
})
