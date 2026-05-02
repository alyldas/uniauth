import { describe, expect, it } from 'vitest'
import packageJson from '../../package.json'
import {
  AuditEventType,
  OtpChannel,
  PASSWORD_PROVIDER_ID,
  SessionStatus,
  UNIAUTH_ATTRIBUTION,
  UniAuthErrorCode,
  VerificationPurpose,
  addSeconds,
  asAuditEventId,
  getUniAuthAttributionNotice,
  toAuditEventCursor,
} from '../../src'
import { createInMemoryAuthKit } from '../../src/testing'
import { assertion, now } from './support.js'

interface PackageMetadata {
  readonly name: string
  readonly license: string
  readonly author: {
    readonly name: string
    readonly email: string
  }
}

function formatPackageLicenseName(license: string): string {
  return license
    .replace(/^PolyForm-/, 'PolyForm ')
    .replace(/-(\d+\.\d+\.\d+)$/, ' License $1')
    .replaceAll('-', ' ')
}

const packageMetadata = packageJson as PackageMetadata
const packageLicense = formatPackageLicenseName(packageMetadata.license)

describe('DefaultAuthService read side and sessions', () => {
  it('exports stable attribution metadata and an About/Legal notice helper', () => {
    expect(UNIAUTH_ATTRIBUTION.packageName).toBe(packageMetadata.name)
    expect(UNIAUTH_ATTRIBUTION.contactEmail).toBe(packageMetadata.author.email)
    expect(UNIAUTH_ATTRIBUTION.license).toBe(packageLicense)
    expect(getUniAuthAttributionNotice()).toBe(
      `This product uses ${packageMetadata.name}. ${UNIAUTH_ATTRIBUTION.copyright} License: ${packageLicense}. Licensing contact: ${packageMetadata.author.email}.`,
    )
    expect(
      getUniAuthAttributionNotice({
        includeContact: false,
        includeLicense: false,
        productName: 'Example App',
      }),
    ).toBe(`Example App uses ${packageMetadata.name}. ${UNIAUTH_ATTRIBUTION.copyright}`)
  })

  it('creates a local user, identity, and session for a new sign-in', async () => {
    const { service, store } = createInMemoryAuthKit()

    const result = await service.signIn({ assertion: assertion(), now })

    expect(result.isNewUser).toBe(true)
    expect(result.isNewIdentity).toBe(true)
    expect(result.user.email).toBe('alice@example.com')
    expect(result.identity.email).toBe('alice@example.com')
    expect(result.session.status).toBe(SessionStatus.Active)
    expect(result.sessionToken).toBeTypeOf('string')
    expect(result.sessionToken).not.toBe(result.session.id)
    expect(result.session.tokenHash).not.toBe(result.sessionToken)
    expect(await service.getUser(result.user.id)).toBe(result.user)
    expect(await service.resolveSession({ sessionToken: result.sessionToken, now })).toBe(
      result.session,
    )
    expect(store.listUsers()).toHaveLength(1)
    expect(store.listIdentities()).toHaveLength(1)
    expect(store.listSessions()).toHaveLength(1)
    expect(store.listAuditEvents().map((event) => event.type)).toContain(
      AuditEventType.SessionCreated,
    )
  })

  it('resolves a trusted session context and can optionally touch activity', async () => {
    const { service, store } = createInMemoryAuthKit()
    const result = await service.signIn({ assertion: assertion(), now })
    const untouched = await service.resolveSessionContext({
      sessionToken: result.sessionToken,
      now,
    })
    const touchedAt = addSeconds(now, 60)
    const touched = await service.resolveSessionContext({
      sessionToken: result.sessionToken,
      touch: true,
      now: touchedAt,
    })

    expect(untouched).toEqual({
      session: result.session,
      user: result.user,
    })
    expect(touched).toEqual({
      session: {
        ...result.session,
        lastSeenAt: touchedAt,
      },
      user: result.user,
    })
    expect(store.listSessions()).toEqual([
      {
        ...result.session,
        lastSeenAt: touchedAt,
      },
    ])
  })

  it('touches active sessions without rewinding last seen activity', async () => {
    const { service } = createInMemoryAuthKit()
    const result = await service.signIn({ assertion: assertion(), now })
    const touchedAt = addSeconds(now, 60)
    const touched = await service.touchSession({
      sessionId: result.session.id,
      now: touchedAt,
    })

    expect(touched.lastSeenAt).toEqual(touchedAt)
    expect(
      await service.touchSession({
        sessionId: result.session.id,
        now: addSeconds(now, 30),
      }),
    ).toBe(touched)
  })

  it('treats disabled users behind an active session as a neutral session miss', async () => {
    const { service, store } = createInMemoryAuthKit()
    const result = await service.signIn({ assertion: assertion(), now })

    await store.userRepo.update(result.user.id, { disabledAt: addSeconds(now, 10) })

    await expect(
      service.resolveSessionContext({
        sessionToken: result.sessionToken,
        touch: true,
        now: addSeconds(now, 20),
      }),
    ).rejects.toMatchObject({
      code: UniAuthErrorCode.SessionNotFound,
      message: 'Session was not found.',
    })
    expect(store.listSessions()).toEqual([result.session])
  })

  it('reads local credentials and verifications through the public service surface', async () => {
    const { service } = createInMemoryAuthKit()
    const signedIn = await service.signIn({
      assertion: assertion({
        provider: 'email',
        providerUserId: 'credential-reader',
        email: 'credential-reader@example.com',
        emailVerified: true,
      }),
      now,
    })
    const credential = await service.setPassword({
      userId: signedIn.user.id,
      email: 'credential-reader@example.com',
      password: 'secret-password',
      now,
    })
    const createdVerification = await service.createVerification({
      purpose: VerificationPurpose.SignIn,
      target: 'credential-reader@example.com',
      secret: '123456',
      now,
    })

    expect(await service.getUserCredentials(signedIn.user.id)).toEqual([credential])
    expect(await service.getVerification(createdVerification.verification.id)).toEqual(
      createdVerification.verification,
    )
    expect(await service.getAccountSecuritySnapshot(signedIn.user.id)).toEqual({
      user: {
        id: signedIn.user.id,
        email: 'credential-reader@example.com',
        displayName: 'Alice',
        createdAt: signedIn.user.createdAt,
        updatedAt: signedIn.user.updatedAt,
      },
      identities: [
        {
          id: signedIn.identity.id,
          provider: signedIn.identity.provider,
          status: signedIn.identity.status,
          email: 'credential-reader@example.com',
          emailVerified: true,
          createdAt: signedIn.identity.createdAt,
          updatedAt: signedIn.identity.updatedAt,
        },
        {
          provider: PASSWORD_PROVIDER_ID,
          status: 'active',
          email: 'credential-reader@example.com',
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

  it('reads audit events through the public service surface with newest-first filtering', async () => {
    const { service } = createInMemoryAuthKit()
    const signedIn = await service.signIn({
      assertion: assertion({
        provider: 'email',
        providerUserId: 'audit-reader',
        email: 'audit-reader@example.com',
        emailVerified: true,
      }),
      now,
    })
    const verification = await service.createVerification({
      purpose: VerificationPurpose.SignIn,
      target: 'audit-reader@example.com',
      secret: '123456',
      now: addSeconds(now, 5),
    })
    await service.revokeSession(signedIn.session.id)

    const allEvents = await service.getAuditEvents()
    const userEvents = await service.getAuditEvents({ userId: signedIn.user.id, limit: 3 })
    const sessionEvents = await service.getAuditEvents({ sessionId: signedIn.session.id, limit: 2 })
    const olderUserEvents = await service.getAuditEvents({
      userId: signedIn.user.id,
      before: toAuditEventCursor(allEvents[0]!),
      limit: 5,
    })
    const sameTimestampOlderEvents = await service.getAuditEvents({
      userId: signedIn.user.id,
      before: toAuditEventCursor(userEvents[1]!),
      limit: 5,
    })
    const sameTimestampNewerEvents = await service.getAuditEvents({
      userId: signedIn.user.id,
      after: toAuditEventCursor(userEvents[2]!),
      limit: 5,
    })

    expect(allEvents.map((event) => event.type)).toEqual([
      AuditEventType.SessionRevoked,
      AuditEventType.VerificationCreated,
      AuditEventType.SignIn,
      AuditEventType.SessionCreated,
    ])
    expect(userEvents.map((event) => event.type)).toEqual([
      AuditEventType.SessionRevoked,
      AuditEventType.SignIn,
      AuditEventType.SessionCreated,
    ])
    expect(sessionEvents.map((event) => event.type)).toEqual([
      AuditEventType.SessionRevoked,
      AuditEventType.SignIn,
    ])
    expect(olderUserEvents.map((event) => event.type)).toEqual([
      AuditEventType.SignIn,
      AuditEventType.SessionCreated,
    ])
    expect(sameTimestampOlderEvents.map((event) => event.type)).toEqual([
      AuditEventType.SessionCreated,
    ])
    expect(sameTimestampNewerEvents.map((event) => event.type)).toEqual([
      AuditEventType.SessionRevoked,
      AuditEventType.SignIn,
    ])
    expect(
      await service.getAuditEvents({
        type: AuditEventType.VerificationCreated,
        limit: 5,
      }),
    ).toEqual([
      expect.objectContaining({
        type: AuditEventType.VerificationCreated,
        metadata: {
          purpose: VerificationPurpose.SignIn,
          verificationId: verification.verification.id,
        },
      }),
    ])
  })

  it('reads a trusted account inspection snapshot through the public service surface', async () => {
    const { service } = createInMemoryAuthKit()
    const signedIn = await service.signIn({
      assertion: assertion({
        provider: 'email',
        providerUserId: 'inspection-reader',
        email: 'inspection-reader@example.com',
        emailVerified: true,
      }),
      now,
    })

    await service.createVerification({
      purpose: VerificationPurpose.SignIn,
      target: 'inspection-reader@example.com',
      secret: '123456',
      now: addSeconds(now, 5),
    })
    await service.revokeSession(signedIn.session.id)

    expect(
      await service.getAccountInspectionSnapshot({
        userId: signedIn.user.id,
        auditLimit: 3,
      }),
    ).toEqual({
      account: await service.getAccountSecuritySnapshot(signedIn.user.id),
      auditEvents: [
        {
          id: expect.any(String),
          type: AuditEventType.SessionRevoked,
          occurredAt: expect.any(Date),
          userId: signedIn.user.id,
          sessionId: signedIn.session.id,
        },
        {
          id: expect.any(String),
          type: AuditEventType.SignIn,
          occurredAt: expect.any(Date),
          userId: signedIn.user.id,
          identityId: signedIn.identity.id,
          sessionId: signedIn.session.id,
        },
        {
          id: expect.any(String),
          type: AuditEventType.SessionCreated,
          occurredAt: expect.any(Date),
          userId: signedIn.user.id,
          sessionId: signedIn.session.id,
        },
      ],
    })
    expect(
      (await service.getAccountInspectionSnapshot({ userId: signedIn.user.id })).auditEvents,
    ).toHaveLength(3)
  })

  it('bulk-revokes active user sessions while optionally keeping one session active', async () => {
    const { service, store } = createInMemoryAuthKit()
    const signedIn = await service.signIn({ assertion: assertion(), now })
    const second = await service.createSession({
      userId: signedIn.user.id,
      now: addSeconds(now, 10),
    })
    const third = await service.createSession({
      userId: signedIn.user.id,
      now: addSeconds(now, 20),
    })

    const result = await service.revokeUserSessions({
      userId: signedIn.user.id,
      exceptSessionId: signedIn.session.id,
      now: addSeconds(now, 30),
    })

    expect(result).toEqual({
      userId: signedIn.user.id,
      revokedSessionIds: [second.session.id, third.session.id],
    })
    expect(await service.getUserSessions(signedIn.user.id)).toMatchObject([
      { id: signedIn.session.id, status: SessionStatus.Active },
      { id: second.session.id, status: SessionStatus.Revoked },
      { id: third.session.id, status: SessionStatus.Revoked },
    ])
    expect(
      store
        .listAuditEvents()
        .filter((event) => event.type === AuditEventType.SessionRevoked)
        .map((event) => event.sessionId),
    ).toEqual([second.session.id, third.session.id])
  })

  it('honors explicit zero TTL options in the in-memory testing kit', async () => {
    const { service } = createInMemoryAuthKit({
      clock: { now: () => now },
      sessionTtlSeconds: 0,
      verificationTtlSeconds: 0,
    })

    const result = await service.signIn({ assertion: assertion() })
    const verification = await service.createVerification({
      purpose: VerificationPurpose.SignIn,
      target: 'ttl@example.com',
    })

    expect(result.session.expiresAt).toEqual(now)
    expect(verification.verification.expiresAt).toEqual(now)
  })

  it('rejects invalid session tokens, TTLs, and expiration inputs', async () => {
    const { service } = createInMemoryAuthKit()
    const signedIn = await service.signIn({ assertion: assertion(), now })
    const expired = await service.createSession({
      userId: signedIn.user.id,
      expiresAt: now,
      now,
    })

    await expect(service.resolveSession({ sessionToken: '   ', now })).rejects.toMatchObject({
      code: UniAuthErrorCode.InvalidInput,
    })
    await expect(service.resolveSession({ sessionToken: 'missing', now })).rejects.toMatchObject({
      code: UniAuthErrorCode.SessionNotFound,
    })
    await expect(
      service.resolveSession({ sessionToken: expired.sessionToken, now }),
    ).rejects.toMatchObject({
      code: UniAuthErrorCode.SessionNotFound,
    })
    await expect(
      service.touchSession({
        sessionId: expired.session.id,
        now,
      }),
    ).rejects.toMatchObject({
      code: UniAuthErrorCode.SessionNotFound,
    })
    await expect(
      service.createSession({
        userId: signedIn.user.id,
        expiresAt: addSeconds(now, -1),
        now,
      }),
    ).rejects.toMatchObject({ code: UniAuthErrorCode.InvalidInput })
    await expect(service.getAuditEvents({ limit: 0 })).rejects.toMatchObject({
      code: UniAuthErrorCode.InvalidInput,
    })
    await expect(
      service.getAuditEvents({
        before: {
          occurredAt: new Date(Number.NaN),
          id: asAuditEventId('audit-cursor'),
        },
      }),
    ).rejects.toMatchObject({
      code: UniAuthErrorCode.InvalidInput,
    })
    await expect(
      service.getAuditEvents({
        // @ts-expect-error runtime validation for legacy callers
        before: new Date(),
      }),
    ).rejects.toMatchObject({
      code: UniAuthErrorCode.InvalidInput,
    })
    await expect(
      service.getAuditEvents({
        // @ts-expect-error runtime validation for untyped callers
        before: 123,
      }),
    ).rejects.toMatchObject({
      code: UniAuthErrorCode.InvalidInput,
    })
    await expect(
      service.getAuditEvents({
        before: {
          occurredAt: now,
          id: asAuditEventId('   '),
        },
      }),
    ).rejects.toMatchObject({
      code: UniAuthErrorCode.InvalidInput,
    })
    await expect(
      service.getAuditEvents({
        before: {
          occurredAt: now,
          // @ts-expect-error runtime validation for untyped callers
          id: 123,
        },
      }),
    ).rejects.toMatchObject({
      code: UniAuthErrorCode.InvalidInput,
    })
    await expect(
      service.getAuditEvents({
        // @ts-expect-error runtime validation for untyped callers
        type: '   ',
      }),
    ).rejects.toMatchObject({
      code: UniAuthErrorCode.InvalidInput,
    })
    await expect(
      service.createSession({
        userId: signedIn.user.id,
        expiresAt: new Date('invalid'),
        now,
      }),
    ).rejects.toMatchObject({ code: UniAuthErrorCode.InvalidInput })
    await expect(
      service.createSession({
        userId: signedIn.user.id,
        now: new Date('invalid'),
      }),
    ).rejects.toMatchObject({ code: UniAuthErrorCode.InvalidInput })

    await expect(
      createInMemoryAuthKit({ sessionTtlSeconds: -1 }).service.signIn({
        assertion: assertion(),
        now,
      }),
    ).rejects.toMatchObject({ code: UniAuthErrorCode.InvalidInput })
    await expect(
      createInMemoryAuthKit({ sessionTtlSeconds: Number.NaN }).service.signIn({
        assertion: assertion(),
        now,
      }),
    ).rejects.toMatchObject({ code: UniAuthErrorCode.InvalidInput })
    await expect(
      service.touchSession({
        sessionId: signedIn.session.id,
        now: new Date('invalid'),
      }),
    ).rejects.toMatchObject({ code: UniAuthErrorCode.InvalidInput })
  })

  it('rejects invalid verification TTL and creation time inputs', async () => {
    const { service } = createInMemoryAuthKit()

    await expect(
      service.createVerification({
        purpose: VerificationPurpose.SignIn,
        target: 'ttl@example.com',
        ttlSeconds: -1,
        now,
      }),
    ).rejects.toMatchObject({ code: UniAuthErrorCode.InvalidInput })
    await expect(
      service.createVerification({
        purpose: VerificationPurpose.SignIn,
        target: 'nan@example.com',
        ttlSeconds: Number.NaN,
        now,
      }),
    ).rejects.toMatchObject({ code: UniAuthErrorCode.InvalidInput })
    await expect(
      service.createVerification({
        purpose: VerificationPurpose.SignIn,
        target: 'invalid-now@example.com',
        now: new Date('invalid'),
      }),
    ).rejects.toMatchObject({ code: UniAuthErrorCode.InvalidInput })

    await expect(
      createInMemoryAuthKit({ verificationTtlSeconds: -1 }).service.createVerification({
        purpose: VerificationPurpose.SignIn,
        target: 'runtime-negative@example.com',
        now,
      }),
    ).rejects.toMatchObject({ code: UniAuthErrorCode.InvalidInput })
    await expect(
      createInMemoryAuthKit({ verificationTtlSeconds: Number.NaN }).service.createVerification({
        purpose: VerificationPurpose.SignIn,
        target: 'runtime-nan@example.com',
        now,
      }),
    ).rejects.toMatchObject({ code: UniAuthErrorCode.InvalidInput })
  })

  it('uses the runtime clock when resolving sessions and finishing OTP sign-in', async () => {
    const { service } = createInMemoryAuthKit({
      clock: { now: () => now },
    })
    const signedIn = await service.signIn({
      assertion: assertion({
        providerUserId: 'clock-session',
        email: 'clock-session@example.com',
      }),
    })

    expect(await service.resolveSession({ sessionToken: signedIn.sessionToken })).toBe(
      signedIn.session,
    )
    expect(await service.touchSession({ sessionId: signedIn.session.id })).toMatchObject({
      id: signedIn.session.id,
      lastSeenAt: now,
    })

    const challenge = await service.startOtpChallenge({
      purpose: VerificationPurpose.SignIn,
      channel: OtpChannel.Email,
      target: 'clock-otp@example.com',
      secret: '123456',
    })
    const finished = await service.finishOtpSignIn({
      verificationId: challenge.verificationId,
      secret: '123456',
      channel: OtpChannel.Email,
    })

    expect(finished.session.status).toBe(SessionStatus.Active)
  })

  it('uses the runtime clock when bulk-revoking user sessions', async () => {
    const { service } = createInMemoryAuthKit({
      clock: { now: () => now },
    })
    const signedIn = await service.signIn({ assertion: assertion() })
    const second = await service.createSession({
      userId: signedIn.user.id,
    })

    expect(await service.revokeUserSessions({ userId: signedIn.user.id })).toEqual({
      userId: signedIn.user.id,
      revokedSessionIds: [signedIn.session.id, second.session.id],
    })
    expect(await service.getUserSessions(signedIn.user.id)).toMatchObject([
      { id: signedIn.session.id, status: SessionStatus.Revoked, revokedAt: now },
      { id: second.session.id, status: SessionStatus.Revoked, revokedAt: now },
    ])
  })
})
