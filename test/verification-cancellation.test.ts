import { describe, expect, it } from 'vitest'
import {
  AuditEventType,
  OtpChannel,
  UniAuthErrorCode,
  VerificationPurpose,
  VerificationStatus,
  addSeconds,
  asVerificationId,
} from '../src'
import { createInMemoryAuthKit } from '../src/testing'
import { now } from './helpers.js'
import { createPostgresTestKit } from './postgres/support.js'

describe('verification cancellation flows', () => {
  it('cancels a pending generic verification and audits the state transition once', async () => {
    const { service, store } = createInMemoryAuthKit({
      clock: { now: () => now },
    })
    const created = await service.createVerification({
      purpose: VerificationPurpose.SignIn,
      target: 'alice@example.com',
      secret: '123456',
      now,
    })

    const cancelled = await service.cancelVerification({
      verificationId: created.verification.id,
      metadata: { reason: 'user_request' },
    })

    expect(cancelled).toMatchObject({
      id: created.verification.id,
      status: VerificationStatus.Pending,
      expiresAt: now,
    })
    await expect(
      service.consumeVerification({
        verificationId: created.verification.id,
        secret: '123456',
        now,
      }),
    ).rejects.toMatchObject({
      code: UniAuthErrorCode.VerificationExpired,
    })
    expect(store.listAuditEvents()).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          type: AuditEventType.VerificationCancelled,
          metadata: {
            verificationId: created.verification.id,
            purpose: VerificationPurpose.SignIn,
            reason: 'user_request',
          },
        }),
      ]),
    )
    await expect(
      service.cancelVerification({
        verificationId: created.verification.id,
        metadata: ['not-a-record'],
        now: addSeconds(now, 1),
      } as unknown as Parameters<typeof service.cancelVerification>[0]),
    ).rejects.toMatchObject({
      code: UniAuthErrorCode.InvalidInput,
    })
  })

  it('keeps cancellation idempotent for consumed and already expired verifications', async () => {
    const { service, store } = createInMemoryAuthKit()
    const consumed = await service.createVerification({
      purpose: VerificationPurpose.SignIn,
      target: 'consumed@example.com',
      secret: '111111',
      now,
    })
    await service.consumeVerification({
      verificationId: consumed.verification.id,
      secret: '111111',
      now,
    })
    const expired = await service.createVerification({
      purpose: VerificationPurpose.Recovery,
      target: 'expired@example.com',
      secret: '222222',
      ttlSeconds: 30,
      now,
    })

    const consumedCancellation = await service.cancelVerification({
      verificationId: consumed.verification.id,
      now: addSeconds(now, 5),
    })
    const expiredCancellation = await service.cancelVerification({
      verificationId: expired.verification.id,
      now: addSeconds(now, 31),
    })

    expect(consumedCancellation.status).toBe(VerificationStatus.Consumed)
    expect(expiredCancellation.expiresAt).toEqual(addSeconds(now, 30))
    expect(
      store
        .listAuditEvents()
        .filter((event) => event.type === AuditEventType.VerificationCancelled),
    ).toHaveLength(0)
  })

  it('cancels OTP challenges and keeps finish and resend on the expired path', async () => {
    const cancellationNow = addSeconds(now, 61)
    const { service } = createInMemoryAuthKit({
      clock: { now: () => cancellationNow },
      verificationResendCooldownSeconds: 0,
    })
    const started = await service.startOtpChallenge({
      purpose: VerificationPurpose.SignIn,
      channel: OtpChannel.Email,
      target: 'otp@example.com',
      secret: '111111',
      now,
    })

    await expect(
      service.cancelOtpChallenge({
        verificationId: started.verificationId,
        channel: OtpChannel.Email,
      }),
    ).resolves.toMatchObject({
      id: started.verificationId,
      expiresAt: cancellationNow,
    })

    await expect(
      service.finishOtpSignIn({
        verificationId: started.verificationId,
        secret: '111111',
        channel: OtpChannel.Email,
        now: cancellationNow,
      }),
    ).rejects.toMatchObject({
      code: UniAuthErrorCode.VerificationExpired,
    })
    await expect(
      service.resendOtpChallenge({
        verificationId: started.verificationId,
        secret: '222222',
        now: cancellationNow,
      }),
    ).rejects.toMatchObject({
      code: UniAuthErrorCode.VerificationExpired,
    })
    await expect(
      service.cancelOtpChallenge({
        verificationId: started.verificationId,
        purpose: VerificationPurpose.Recovery,
        now,
      }),
    ).rejects.toMatchObject({
      code: UniAuthErrorCode.InvalidInput,
    })
  })

  it('cancels magic-link and recovery verifications only through matching helpers', async () => {
    const { service } = createInMemoryAuthKit({
      clock: { now: () => addSeconds(now, 61) },
      verificationResendCooldownSeconds: 0,
    })
    const magic = await service.startEmailMagicLinkSignIn({
      email: 'magic@example.com',
      secret: 'magic-secret',
      createLink: ({ verificationId, secret }) =>
        `https://example.com/magic?verificationId=${verificationId}&secret=${secret}`,
      now,
    })
    const recovery = await service.startEmailPasswordRecovery({
      email: 'recovery@example.com',
      secret: 'recovery-secret',
      createLink: ({ verificationId, secret }) =>
        `https://example.com/recovery?verificationId=${verificationId}&secret=${secret}`,
      now,
    })

    await expect(
      service.cancelEmailMagicLinkSignIn({
        verificationId: magic.verificationId,
      }),
    ).resolves.toMatchObject({
      id: magic.verificationId,
      expiresAt: addSeconds(now, 61),
    })
    await expect(
      service.cancelEmailPasswordRecovery({
        verificationId: recovery.verificationId,
      }),
    ).resolves.toMatchObject({
      id: recovery.verificationId,
      expiresAt: addSeconds(now, 61),
    })
    await expect(
      service.finishEmailMagicLinkSignIn({
        verificationId: magic.verificationId,
        secret: 'magic-secret',
        now: addSeconds(now, 61),
      }),
    ).rejects.toMatchObject({
      code: UniAuthErrorCode.VerificationExpired,
    })
    await expect(
      service.finishEmailPasswordRecovery({
        verificationId: recovery.verificationId,
        secret: 'recovery-secret',
        newPassword: 'new-password-123',
        now: addSeconds(now, 61),
      }),
    ).rejects.toMatchObject({
      code: UniAuthErrorCode.VerificationExpired,
    })
    await expect(
      service.cancelEmailMagicLinkSignIn({
        verificationId: recovery.verificationId,
        now,
      }),
    ).rejects.toMatchObject({
      code: UniAuthErrorCode.InvalidInput,
    })
    await expect(
      service.cancelEmailPasswordRecovery({
        verificationId: magic.verificationId,
        now,
      }),
    ).rejects.toMatchObject({
      code: UniAuthErrorCode.InvalidInput,
    })
  })

  it('uses locked verification reads for cancellation helpers', async () => {
    const { service, store } = createInMemoryAuthKit({
      clock: { now: () => addSeconds(now, 90) },
    })
    const generic = await service.createVerification({
      purpose: VerificationPurpose.SignIn,
      target: 'locked-generic@example.com',
      secret: '111111',
      now,
    })
    const otp = await service.startOtpChallenge({
      purpose: VerificationPurpose.SignIn,
      channel: OtpChannel.Email,
      target: 'locked-otp@example.com',
      secret: '222222',
      now,
    })
    const magic = await service.startEmailMagicLinkSignIn({
      email: 'locked-magic@example.com',
      secret: 'magic-secret',
      createLink: ({ verificationId, secret }) =>
        `https://example.com/magic?verificationId=${verificationId}&secret=${secret}`,
      now,
    })
    const recovery = await service.startEmailPasswordRecovery({
      email: 'locked-recovery@example.com',
      secret: 'recovery-secret',
      createLink: ({ verificationId, secret }) =>
        `https://example.com/recovery?verificationId=${verificationId}&secret=${secret}`,
      now,
    })
    const originalFindById = store.verificationRepo.findById
    const originalFindByIdForUpdate = store.verificationRepo.findByIdForUpdate
    let lockedReads = 0

    store.verificationRepo.findById = async () => {
      throw new Error('unlocked verification read')
    }
    store.verificationRepo.findByIdForUpdate = async (id) => {
      lockedReads += 1
      return originalFindByIdForUpdate(id)
    }

    await expect(
      service.cancelVerification({ verificationId: generic.verification.id }),
    ).resolves.toMatchObject({ id: generic.verification.id })
    await expect(
      service.cancelOtpChallenge({
        verificationId: otp.verificationId,
        channel: OtpChannel.Email,
      }),
    ).resolves.toMatchObject({ id: otp.verificationId })
    await expect(
      service.cancelEmailMagicLinkSignIn({ verificationId: magic.verificationId }),
    ).resolves.toMatchObject({ id: magic.verificationId })
    await expect(
      service.cancelEmailPasswordRecovery({ verificationId: recovery.verificationId }),
    ).resolves.toMatchObject({ id: recovery.verificationId })

    expect(lockedReads).toBe(4)

    store.verificationRepo.findById = originalFindById
    store.verificationRepo.findByIdForUpdate = originalFindByIdForUpdate
  })

  it('returns not found when locked cancellation lookup misses', async () => {
    const { service } = createInMemoryAuthKit()

    await expect(
      service.cancelVerification({
        verificationId: asVerificationId('missing-locked-verification'),
        now,
      }),
    ).rejects.toMatchObject({
      code: UniAuthErrorCode.VerificationNotFound,
    })
  })

  it('keeps Postgres verification cancellation semantics aligned with in-memory behavior', async () => {
    const { service } = await createPostgresTestKit({
      verificationResendCooldownSeconds: 0,
    })
    const started = await service.startOtpChallenge({
      purpose: VerificationPurpose.SignIn,
      channel: OtpChannel.Phone,
      target: '+15551234567',
      secret: '111111',
      now,
    })

    const cancelled = await service.cancelOtpChallenge({
      verificationId: started.verificationId,
      channel: OtpChannel.Phone,
      now,
      metadata: { source: 'postgres' },
    })
    const auditEvents = await service.getAuditEvents({
      type: AuditEventType.VerificationCancelled,
    })

    await expect(
      service.getAuditEvents({
        type: 123,
      } as unknown as Parameters<typeof service.getAuditEvents>[0]),
    ).rejects.toMatchObject({
      code: UniAuthErrorCode.InvalidInput,
      message: 'Audit event type is invalid.',
    })
    expect(cancelled.expiresAt).toEqual(now)
    expect(auditEvents).toEqual([
      expect.objectContaining({
        type: AuditEventType.VerificationCancelled,
        metadata: {
          verificationId: started.verificationId,
          purpose: VerificationPurpose.SignIn,
          source: 'postgres',
        },
      }),
    ])
    await expect(
      service.finishOtpSignIn({
        verificationId: started.verificationId,
        secret: '111111',
        channel: OtpChannel.Phone,
        now,
      }),
    ).rejects.toMatchObject({
      code: UniAuthErrorCode.VerificationExpired,
    })
  })
})
