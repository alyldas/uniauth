import { describe, expect, it } from 'vitest'
import {
  AuditEventType,
  SessionStatus,
  UniAuthErrorCode,
  VerificationPurpose,
  VerificationStatus,
  addSeconds,
  asAuditEventId,
  asCredentialId,
  asIdentityId,
  asSessionId,
  asUserId,
  asVerificationId,
  CredentialType,
  hashSecret,
  toAuditEventCursor,
  type Credential,
  type Session,
  type Verification,
} from '../src'
import { InMemoryAuthStore, InMemoryPasswordHasher } from '../src/testing'
import { identity, now, user } from './helpers.js'

describe('InMemoryAuthStore', () => {
  it('covers repository success and failure paths', async () => {
    const store = new InMemoryAuthStore()
    const createdUser = await store.userRepo.create(user())

    expect(await store.userRepo.findById(createdUser.id)).toBe(createdUser)
    expect(await store.userRepo.update(createdUser.id, { displayName: 'Alice' })).toMatchObject({
      displayName: 'Alice',
    })
    expect(
      await store.userRepo
        .update(asUserId('missing'), { displayName: 'Missing' })
        .catch((caught: unknown) => caught),
    ).toMatchObject({
      code: UniAuthErrorCode.UserNotFound,
    })

    const emailIdentity = await store.identityRepo.create(
      identity({
        email: 'alice@example.com',
        emailVerified: true,
        phone: '+15551234567',
        phoneVerified: true,
      }),
    )
    const secondIdentity = await store.identityRepo.create(
      identity({
        id: asIdentityId('identity-2'),
        provider: 'oauth',
        providerUserId: 'oauth-alice',
      }),
    )

    expect(await store.identityRepo.findById(emailIdentity.id)).toBe(emailIdentity)
    expect(await store.identityRepo.findByProviderUserId('email', 'alice')).toBe(emailIdentity)
    expect(await store.identityRepo.findByProviderUserId('missing', 'missing')).toBeUndefined()
    expect(await store.identityRepo.findByVerifiedEmail(' Alice@Example.com ')).toEqual([
      emailIdentity,
    ])
    expect(await store.identityRepo.findByVerifiedPhone(' +1 (555) 123-4567 ')).toEqual([
      emailIdentity,
    ])
    expect(await store.identityRepo.listByUserId(createdUser.id)).toHaveLength(2)
    expect(
      await store.identityRepo.create(emailIdentity).catch((caught: unknown) => caught),
    ).toMatchObject({
      code: UniAuthErrorCode.IdentityAlreadyLinked,
    })
    expect(
      await store.identityRepo
        .update(secondIdentity.id, {
          provider: emailIdentity.provider,
          providerUserId: emailIdentity.providerUserId,
        })
        .catch((caught: unknown) => caught),
    ).toMatchObject({ code: UniAuthErrorCode.IdentityAlreadyLinked })
    expect(
      await store.identityRepo
        .update(asIdentityId('missing'), {})
        .catch((caught: unknown) => caught),
    ).toMatchObject({
      code: UniAuthErrorCode.IdentityNotFound,
    })
    expect(
      await store.identityRepo.update(secondIdentity.id, { providerUserId: 'oauth-alice-2' }),
    ).toMatchObject({
      providerUserId: 'oauth-alice-2',
    })

    const passwordHasher = new InMemoryPasswordHasher()
    const credential: Credential = {
      id: asCredentialId('credential-1'),
      userId: createdUser.id,
      type: CredentialType.Password,
      subject: 'alice@example.com',
      passwordHash: await passwordHasher.hash('password'),
      createdAt: now,
      updatedAt: now,
    }
    const otherUser = await store.userRepo.create(user('user-2'))
    const secondCredential: Credential = {
      id: asCredentialId('credential-2'),
      userId: otherUser.id,
      type: CredentialType.Password,
      subject: 'second@example.com',
      passwordHash: await passwordHasher.hash('password'),
      createdAt: now,
      updatedAt: now,
    }
    const sameUserCredential: Credential = {
      id: asCredentialId('credential-3'),
      userId: createdUser.id,
      type: CredentialType.Password,
      subject: 'same-user@example.com',
      passwordHash: await passwordHasher.hash('password'),
      createdAt: now,
      updatedAt: now,
    }

    expect(await store.credentialRepo.findPasswordByEmail(credential.subject)).toBeUndefined()
    expect(await store.credentialRepo.create(credential)).toBe(credential)
    expect(await store.credentialRepo.findPasswordByEmail(' Alice@Example.com ')).toBe(credential)
    expect(await store.credentialRepo.findPasswordByUserId(createdUser.id)).toBe(credential)
    expect(await store.credentialRepo.listByUserId(createdUser.id)).toEqual([credential])
    expect(
      await store.credentialRepo.create(credential).catch((caught: unknown) => caught),
    ).toMatchObject({
      code: UniAuthErrorCode.CredentialAlreadyExists,
    })
    expect(
      await store.credentialRepo.create(sameUserCredential).catch((caught: unknown) => caught),
    ).toMatchObject({
      code: UniAuthErrorCode.CredentialAlreadyExists,
    })
    expect(await store.credentialRepo.create(secondCredential)).toBe(secondCredential)
    const updatedPasswordHash = await passwordHasher.hash('new')
    expect(
      await store.credentialRepo.update(credential.id, { passwordHash: updatedPasswordHash }),
    ).toMatchObject({
      passwordHash: updatedPasswordHash,
    })
    expect(
      await store.credentialRepo
        .update(credential.id, { subject: secondCredential.subject })
        .catch((caught: unknown) => caught),
    ).toMatchObject({
      code: UniAuthErrorCode.CredentialAlreadyExists,
    })
    expect(
      await store.credentialRepo
        .update(credential.id, { userId: otherUser.id })
        .catch((caught: unknown) => caught),
    ).toMatchObject({
      code: UniAuthErrorCode.CredentialAlreadyExists,
    })
    expect(
      await store.credentialRepo
        .update(asCredentialId('missing'), {})
        .catch((caught: unknown) => caught),
    ).toMatchObject({
      code: UniAuthErrorCode.CredentialNotFound,
    })

    const verification: Verification = {
      id: asVerificationId('verification-1'),
      purpose: VerificationPurpose.Link,
      target: 'alice@example.com',
      secretHash: hashSecret('123456'),
      status: VerificationStatus.Pending,
      createdAt: now,
      expiresAt: addSeconds(now, 60),
    }

    expect(await store.verificationRepo.findById(verification.id)).toBeUndefined()
    expect(await store.verificationRepo.create(verification)).toBe(verification)
    expect(await store.verificationRepo.findById(verification.id)).toBe(verification)
    expect(
      await store.verificationRepo.update(verification.id, { status: VerificationStatus.Consumed }),
    ).toMatchObject({
      status: VerificationStatus.Consumed,
    })
    expect(
      await store.verificationRepo
        .update(asVerificationId('missing'), {})
        .catch((caught: unknown) => caught),
    ).toMatchObject({
      code: UniAuthErrorCode.VerificationNotFound,
    })

    const session: Session = {
      id: asSessionId('session-1'),
      userId: createdUser.id,
      tokenHash: hashSecret('session-token'),
      status: SessionStatus.Active,
      createdAt: now,
      expiresAt: addSeconds(now, 60),
    }

    expect(await store.sessionRepo.findById(session.id)).toBeUndefined()
    expect(await store.sessionRepo.findByTokenHash(session.tokenHash)).toBeUndefined()
    expect(await store.sessionRepo.create(session)).toBe(session)
    expect(await store.sessionRepo.findById(session.id)).toBe(session)
    expect(await store.sessionRepo.findByTokenHash(session.tokenHash)).toBe(session)
    expect(await store.sessionRepo.listByUserId(createdUser.id)).toEqual([session])
    expect(
      await store.sessionRepo
        .create({ ...session, id: asSessionId('session-duplicate') })
        .catch((caught: unknown) => caught),
    ).toMatchObject({
      code: UniAuthErrorCode.InvalidInput,
    })
    const otherSession: Session = {
      ...session,
      id: asSessionId('session-2'),
      tokenHash: hashSecret('other-session-token'),
    }

    await store.sessionRepo.create(otherSession)
    expect(
      await store.sessionRepo.update(session.id, { status: SessionStatus.Revoked }),
    ).toMatchObject({
      status: SessionStatus.Revoked,
    })
    expect(
      await store.sessionRepo
        .update(session.id, { tokenHash: otherSession.tokenHash })
        .catch((caught: unknown) => caught),
    ).toMatchObject({
      code: UniAuthErrorCode.InvalidInput,
    })
    expect(
      await store.sessionRepo.update(asSessionId('missing'), {}).catch((caught: unknown) => caught),
    ).toMatchObject({
      code: UniAuthErrorCode.SessionNotFound,
    })

    await store.auditLogRepo.append({
      id: asAuditEventId('audit-1'),
      type: AuditEventType.PolicyDenied,
      occurredAt: now,
    })
    await store.auditLogRepo.append({
      id: asAuditEventId('audit-2'),
      type: AuditEventType.SignIn,
      occurredAt: addSeconds(now, 5),
      userId: createdUser.id,
      identityId: emailIdentity.id,
      sessionId: session.id,
    })
    await store.auditLogRepo.append({
      id: asAuditEventId('audit-3'),
      type: AuditEventType.SessionCreated,
      occurredAt: addSeconds(now, 5),
      userId: createdUser.id,
      sessionId: session.id,
    })

    expect(store.listUsers()).toHaveLength(2)
    expect(store.listIdentities()).toHaveLength(2)
    expect(store.listCredentials()).toHaveLength(2)
    expect(store.listVerifications()).toHaveLength(1)
    expect(store.listSessions()).toHaveLength(2)
    expect(store.listAuditEvents()).toHaveLength(3)
    expect(await store.auditLogRepo.list()).toEqual([
      expect.objectContaining({ id: asAuditEventId('audit-3') }),
      expect.objectContaining({ id: asAuditEventId('audit-2') }),
      expect.objectContaining({ id: asAuditEventId('audit-1') }),
    ])
    expect(
      await store.auditLogRepo.list({
        userId: createdUser.id,
        limit: 5,
      }),
    ).toEqual([
      expect.objectContaining({ id: asAuditEventId('audit-3') }),
      expect.objectContaining({ id: asAuditEventId('audit-2') }),
    ])
    expect(
      await store.auditLogRepo.list({
        identityId: emailIdentity.id,
        sessionId: session.id,
      }),
    ).toEqual([expect.objectContaining({ id: asAuditEventId('audit-2') })])
    expect(
      await store.auditLogRepo.list({
        before: toAuditEventCursor({
          id: asAuditEventId('audit-3'),
          type: AuditEventType.SessionCreated,
          occurredAt: addSeconds(now, 5),
        }),
      }),
    ).toEqual([
      expect.objectContaining({ id: asAuditEventId('audit-2') }),
      expect.objectContaining({ id: asAuditEventId('audit-1') }),
    ])
    expect(
      await store.auditLogRepo.list({
        after: toAuditEventCursor({
          id: asAuditEventId('audit-2'),
          type: AuditEventType.SignIn,
          occurredAt: addSeconds(now, 5),
        }),
      }),
    ).toEqual([expect.objectContaining({ id: asAuditEventId('audit-3') })])
  })

  it('rolls back outer state while allowing nested transaction reuse', async () => {
    const store = new InMemoryAuthStore()
    const createdUser = user('transaction-user')

    const nestedResult = await store.run(async () => {
      await store.userRepo.create(createdUser)

      return store.run(async () => {
        await store.auditLogRepo.append({
          id: asAuditEventId('audit-nested'),
          type: AuditEventType.SignIn,
          occurredAt: now,
          userId: createdUser.id,
        })

        return 'nested-ok'
      })
    })

    expect(nestedResult).toBe('nested-ok')
    expect(store.listUsers()).toHaveLength(1)
    expect(store.listAuditEvents()).toHaveLength(1)

    await expect(
      store.run(async () => {
        await store.userRepo.create(user('rollback-user'))
        await store.auditLogRepo.append({
          id: asAuditEventId('audit-rollback'),
          type: AuditEventType.PolicyDenied,
          occurredAt: now,
        })

        throw new Error('rollback')
      }),
    ).rejects.toThrow('rollback')

    expect(store.listUsers().map((entry) => entry.id)).toEqual([createdUser.id])
    expect(store.listAuditEvents().map((event) => event.id)).toEqual([
      asAuditEventId('audit-nested'),
    ])
  })

  it('hashes in-memory passwords with the test scrypt adapter', async () => {
    const passwordHasher = new InMemoryPasswordHasher()
    const passwordHash = await passwordHasher.hash('correct-password')

    expect(passwordHash).toMatch(/^test-password:scrypt:/)
    expect(await passwordHasher.verify('correct-password', passwordHash)).toBe(true)
    expect(await passwordHasher.verify('wrong-password', passwordHash)).toBe(false)
    expect(await passwordHasher.verify('correct-password', 'sha256:not-a-password-hash')).toBe(
      false,
    )
  })
})
