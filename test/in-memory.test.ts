import { describe, expect, it } from 'vitest'
import {
  SessionStatus,
  UniAuthErrorCode,
  VerificationPurpose,
  VerificationStatus,
  addSeconds,
  asAuditEventId,
  asIdentityId,
  asSessionId,
  asUserId,
  asVerificationId,
  hashSecret,
  type Session,
  type Verification,
} from '../src'
import { InMemoryAuthStore } from '../src/testing'
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
      status: SessionStatus.Active,
      createdAt: now,
      expiresAt: addSeconds(now, 60),
    }

    expect(await store.sessionRepo.findById(session.id)).toBeUndefined()
    expect(await store.sessionRepo.create(session)).toBe(session)
    expect(await store.sessionRepo.findById(session.id)).toBe(session)
    expect(await store.sessionRepo.listByUserId(createdUser.id)).toEqual([session])
    expect(
      await store.sessionRepo.update(session.id, { status: SessionStatus.Revoked }),
    ).toMatchObject({
      status: SessionStatus.Revoked,
    })
    expect(
      await store.sessionRepo.update(asSessionId('missing'), {}).catch((caught: unknown) => caught),
    ).toMatchObject({
      code: UniAuthErrorCode.SessionNotFound,
    })

    await store.auditLogRepo.append({
      id: asAuditEventId('audit-1'),
      type: 'auth.policy_denied',
      occurredAt: now,
    })

    expect(store.listUsers()).toHaveLength(1)
    expect(store.listIdentities()).toHaveLength(2)
    expect(store.listVerifications()).toHaveLength(1)
    expect(store.listSessions()).toHaveLength(1)
    expect(store.listAuditEvents()).toHaveLength(1)
  })
})
