import { describe, expect, it } from 'vitest'
import {
  DefaultAuthService,
  OtpChannel,
  RateLimitAction,
  SessionStatus,
  UniAuthErrorCode,
  VerificationPurpose,
  VerificationStatus,
  addSeconds,
  getRateLimitedErrorDetails,
  type EmailSender,
} from '../src'
import { InMemoryAuthStore, createInMemoryAuthKit } from '../src/testing'
import { assertion, now } from './helpers.js'
import { createPostgresTestKit } from './postgres/support.js'

describe('verification resend execution flows', () => {
  it('resends email OTP challenges with cooldown enforcement and replacement semantics', async () => {
    const { service, emailSender, store } = createInMemoryAuthKit({
      clock: { now: () => now },
      verificationResendCooldownSeconds: 60,
    })
    const started = await service.startOtpChallenge({
      purpose: VerificationPurpose.SignIn,
      channel: OtpChannel.Email,
      target: 'alice@example.com',
      secret: '111111',
      metadata: { requestId: 'req-1' },
      now,
    })

    const cooldownError = await service
      .resendOtpChallenge({
        verificationId: started.verificationId,
        secret: '222222',
        now: addSeconds(now, 30),
      })
      .catch((caught: unknown) => caught)

    expect(getRateLimitedErrorDetails(cooldownError)).toEqual({
      action: RateLimitAction.OtpResend,
      retryAfterSeconds: 30,
      resetAt: addSeconds(now, 60).toISOString(),
    })

    const resent = await service.resendOtpChallenge({
      verificationId: started.verificationId,
      secret: '222222',
      metadata: { traceId: 'trace-1' },
      now: addSeconds(now, 61),
    })

    expect(resent.verificationId).not.toBe(started.verificationId)
    expect(resent.delivery).toBe(OtpChannel.Email)
    expect(emailSender.listMessages()).toEqual([
      expect.objectContaining({
        to: 'alice@example.com',
        text: 'Your sign-in code is 111111.',
      }),
      expect.objectContaining({
        to: 'alice@example.com',
        text: 'Your sign-in code is 222222.',
      }),
    ])
    expect(store.listVerifications()).toEqual([
      expect.objectContaining({
        id: started.verificationId,
        status: VerificationStatus.Pending,
        expiresAt: addSeconds(now, 61),
      }),
      expect.objectContaining({
        id: resent.verificationId,
        status: VerificationStatus.Pending,
      }),
    ])
    await expect(service.getVerification(resent.verificationId)).resolves.toMatchObject({
      metadata: {
        requestId: 'req-1',
        traceId: 'trace-1',
      },
    })

    const oldSecretError = await service
      .finishOtpSignIn({
        verificationId: started.verificationId,
        secret: '111111',
        channel: OtpChannel.Email,
        now: addSeconds(now, 61),
      })
      .catch((caught: unknown) => caught)

    expect(oldSecretError).toMatchObject({
      code: UniAuthErrorCode.VerificationExpired,
    })

    const signedIn = await service.finishOtpSignIn({
      verificationId: resent.verificationId,
      secret: '222222',
      channel: OtpChannel.Email,
      now: addSeconds(now, 61),
    })

    expect(signedIn.session.status).toBe(SessionStatus.Active)
  })

  it('keeps phone OTP resend behavior aligned with email replacement semantics', async () => {
    const resendNow = addSeconds(now, 61)
    const { service, smsSender } = createInMemoryAuthKit({
      clock: { now: () => resendNow },
      verificationResendCooldownSeconds: 0,
    })
    const started = await service.startOtpChallenge({
      purpose: VerificationPurpose.SignIn,
      channel: OtpChannel.Phone,
      target: '+15551234567',
      secret: '111111',
      now,
    })
    const resent = await service.resendOtpChallenge({
      verificationId: started.verificationId,
      secret: '222222',
    })

    expect(resent.verificationId).not.toBe(started.verificationId)
    expect(smsSender.listMessages()).toEqual([
      expect.objectContaining({
        to: '+15551234567',
        text: 'Your sign-in code is 111111.',
      }),
      expect.objectContaining({
        to: '+15551234567',
        text: 'Your sign-in code is 222222.',
      }),
    ])
    await expect(
      service.finishOtpSignIn({
        verificationId: started.verificationId,
        secret: '111111',
        channel: OtpChannel.Phone,
        now: resendNow,
      }),
    ).rejects.toMatchObject({
      code: UniAuthErrorCode.VerificationExpired,
    })
  })

  it('rejects resend for consumed and expired verifications', async () => {
    const { service } = createInMemoryAuthKit({
      verificationResendCooldownSeconds: 0,
    })
    const consumed = await service.startOtpChallenge({
      purpose: VerificationPurpose.SignIn,
      channel: OtpChannel.Email,
      target: 'consumed@example.com',
      secret: '111111',
      now,
    })
    await service.finishOtpSignIn({
      verificationId: consumed.verificationId,
      secret: '111111',
      channel: OtpChannel.Email,
      now,
    })

    await expect(
      service.resendOtpChallenge({
        verificationId: consumed.verificationId,
        secret: '222222',
        now,
      }),
    ).rejects.toMatchObject({
      code: UniAuthErrorCode.VerificationConsumed,
    })

    const expired = await service.startOtpChallenge({
      purpose: VerificationPurpose.SignIn,
      channel: OtpChannel.Email,
      target: 'expired@example.com',
      secret: '333333',
      ttlSeconds: 30,
      now,
    })

    await expect(
      service.resendOtpChallenge({
        verificationId: expired.verificationId,
        secret: '444444',
        now: addSeconds(now, 31),
      }),
    ).rejects.toMatchObject({
      code: UniAuthErrorCode.VerificationExpired,
    })
  })

  it('keeps the previous OTP verification usable when resend delivery fails before replacement', async () => {
    const store = new InMemoryAuthStore()
    const messages: Array<{ to: string; text: string }> = []
    let sendAttempts = 0
    const emailSender: EmailSender = {
      sendEmail: async (input) => {
        sendAttempts += 1

        if (sendAttempts === 2) {
          throw new Error('Delivery failed.')
        }

        messages.push({ to: input.to, text: input.text })
      },
    }
    const service = new DefaultAuthService({
      repos: store,
      emailSender,
      clock: { now: () => now },
      verificationResendCooldownSeconds: 0,
    })
    const started = await service.startOtpChallenge({
      purpose: VerificationPurpose.SignIn,
      channel: OtpChannel.Email,
      target: 'delivery@example.com',
      secret: '111111',
      now,
    })
    const resendError = await service
      .resendOtpChallenge({
        verificationId: started.verificationId,
        secret: '222222',
        now,
      })
      .catch((caught: unknown) => caught)

    expect(resendError).toBeInstanceOf(Error)
    expect(messages).toEqual([{ to: 'delivery@example.com', text: 'Your sign-in code is 111111.' }])
    expect(store.listVerifications()).toEqual([
      expect.objectContaining({
        id: started.verificationId,
        status: VerificationStatus.Pending,
      }),
      expect.objectContaining({
        status: VerificationStatus.Pending,
      }),
    ])

    const signedIn = await service.finishOtpSignIn({
      verificationId: started.verificationId,
      secret: '111111',
      channel: OtpChannel.Email,
      now,
    })

    expect(signedIn.session.status).toBe(SessionStatus.Active)
  })

  it('resends magic links with fresh secrets and leaves the previous link valid when replacement fails early', async () => {
    const { service, emailSender } = createInMemoryAuthKit({
      clock: { now: () => now },
      verificationResendCooldownSeconds: 0,
    })
    const started = await service.startEmailMagicLinkSignIn({
      email: 'alice@example.com',
      secret: 'magic-1',
      createLink: ({ verificationId, secret }) =>
        `https://app.example.test/auth/magic?vid=${verificationId}&token=${secret}`,
      now,
    })
    const resent = await service.resendEmailMagicLinkSignIn({
      verificationId: started.verificationId,
      metadata: { source: 'resend' },
      createLink: ({ verificationId, secret }) =>
        `https://app.example.test/auth/magic?vid=${verificationId}&token=${secret}`,
    })
    const resentSecret = extractLinkToken(emailSender.listMessages()[1]?.text ?? '')

    expect(resent.verificationId).not.toBe(started.verificationId)
    await expect(
      service.finishEmailMagicLinkSignIn({
        verificationId: started.verificationId,
        secret: 'magic-1',
        now,
      }),
    ).rejects.toMatchObject({
      code: UniAuthErrorCode.VerificationExpired,
    })

    const signedIn = await service.finishEmailMagicLinkSignIn({
      verificationId: resent.verificationId,
      secret: resentSecret,
      now,
    })

    expect(signedIn.session.status).toBe(SessionStatus.Active)
    await expect(service.getVerification(resent.verificationId)).resolves.toMatchObject({
      metadata: {
        source: 'resend',
      },
    })

    const secondKit = createInMemoryAuthKit({
      clock: { now: () => now },
      verificationResendCooldownSeconds: 0,
    })
    const initial = await secondKit.service.startEmailMagicLinkSignIn({
      email: 'bob@example.com',
      secret: 'magic-1',
      createLink: ({ verificationId, secret }) =>
        `https://app.example.test/auth/magic?vid=${verificationId}&token=${secret}`,
      now,
    })
    const resendError = await secondKit.service
      .resendEmailMagicLinkSignIn({
        verificationId: initial.verificationId,
        secret: 'magic-2',
        createLink: () => {
          throw new Error('Link failed.')
        },
        now,
      })
      .catch((caught: unknown) => caught)

    expect(resendError).toBeInstanceOf(Error)
    expect(secondKit.emailSender.listMessages()).toHaveLength(1)

    const fallbackSignIn = await secondKit.service.finishEmailMagicLinkSignIn({
      verificationId: initial.verificationId,
      secret: 'magic-1',
      now,
    })

    expect(fallbackSignIn.session.status).toBe(SessionStatus.Active)
    expect(emailSender.listMessages()).toHaveLength(2)
  })

  it('rejects email-link resend without an email sender', async () => {
    const magicKit = createInMemoryAuthKit({
      verificationResendCooldownSeconds: 0,
    })
    const magic = await magicKit.service.startEmailMagicLinkSignIn({
      email: 'senderless-magic@example.com',
      secret: 'magic-1',
      createLink: ({ verificationId, secret }) =>
        `https://app.example.test/auth/magic?vid=${verificationId}&token=${secret}`,
      now,
    })
    const magicWithoutSender = new DefaultAuthService({
      repos: magicKit.store,
      transaction: magicKit.store,
      verificationResendCooldownSeconds: 0,
    })

    await expect(
      magicWithoutSender.resendEmailMagicLinkSignIn({
        verificationId: magic.verificationId,
        createLink: ({ verificationId, secret }) =>
          `https://app.example.test/auth/magic?vid=${verificationId}&token=${secret}`,
        now,
      }),
    ).rejects.toMatchObject({
      code: UniAuthErrorCode.InvalidInput,
    })

    const recoveryKit = createInMemoryAuthKit({
      verificationResendCooldownSeconds: 0,
    })
    const initial = await recoveryKit.service.signIn({
      assertion: assertion({ provider: 'oauth', providerUserId: 'senderless-oauth' }),
      now,
    })
    await recoveryKit.service.setPassword({
      userId: initial.user.id,
      email: 'senderless-recovery@example.com',
      password: 'password',
      now,
    })
    const recovery = await recoveryKit.service.startEmailPasswordRecovery({
      email: 'senderless-recovery@example.com',
      secret: 'recovery-1',
      createLink: ({ verificationId, secret }) =>
        `https://app.example.test/auth/recovery?vid=${verificationId}&token=${secret}`,
      now,
    })
    const recoveryWithoutSender = new DefaultAuthService({
      repos: recoveryKit.store,
      transaction: recoveryKit.store,
      verificationResendCooldownSeconds: 0,
    })

    await expect(
      recoveryWithoutSender.resendEmailPasswordRecovery({
        verificationId: recovery.verificationId,
        createLink: ({ verificationId, secret }) =>
          `https://app.example.test/auth/recovery?vid=${verificationId}&token=${secret}`,
        now,
      }),
    ).rejects.toMatchObject({
      code: UniAuthErrorCode.InvalidInput,
    })
  })

  it('resends password recovery links with fresh secrets and expires the previous verification', async () => {
    const { service, emailSender } = createInMemoryAuthKit({
      clock: { now: () => now },
      verificationResendCooldownSeconds: 0,
    })
    const initial = await service.signIn({
      assertion: assertion({ provider: 'oauth', providerUserId: 'alice-oauth' }),
      now,
    })
    await service.setPassword({
      userId: initial.user.id,
      email: 'alice@example.com',
      password: 'old-password',
      now,
    })

    const recovery = await service.startEmailPasswordRecovery({
      email: 'alice@example.com',
      secret: 'recovery-1',
      metadata: { requestId: 'req-1' },
      createLink: ({ verificationId, secret }) =>
        `https://app.example.test/auth/recovery?vid=${verificationId}&token=${secret}`,
      now,
    })
    const resent = await service.resendEmailPasswordRecovery({
      verificationId: recovery.verificationId,
      createLink: ({ verificationId, secret }) =>
        `https://app.example.test/auth/recovery?vid=${verificationId}&token=${secret}`,
    })
    const resentSecret = extractLinkToken(emailSender.listMessages()[1]?.text ?? '')

    expect(resent.verificationId).not.toBe(recovery.verificationId)
    await expect(
      service.finishEmailPasswordRecovery({
        verificationId: recovery.verificationId,
        secret: 'recovery-1',
        newPassword: 'new-password',
        now,
      }),
    ).rejects.toMatchObject({
      code: UniAuthErrorCode.VerificationExpired,
    })

    await service.finishEmailPasswordRecovery({
      verificationId: resent.verificationId,
      secret: resentSecret,
      newPassword: 'new-password',
      now,
    })
    await expect(service.getVerification(resent.verificationId)).resolves.toMatchObject({
      metadata: {
        requestId: 'req-1',
      },
    })

    const signedIn = await service.signInWithPassword({
      email: 'alice@example.com',
      password: 'new-password',
      now,
    })

    expect(signedIn.user.id).toBe(initial.user.id)
  })

  it('keeps Postgres resend execution aligned with in-memory semantics', async () => {
    const { service, emailSender } = await createPostgresTestKit({
      verificationResendCooldownSeconds: 0,
    })
    const started = await service.startOtpChallenge({
      purpose: VerificationPurpose.SignIn,
      channel: OtpChannel.Email,
      target: 'pg-alice@example.com',
      secret: '111111',
      now,
    })
    const resent = await service.resendOtpChallenge({
      verificationId: started.verificationId,
      secret: '222222',
      now,
    })

    expect(resent.verificationId).not.toBe(started.verificationId)
    expect(emailSender.listMessages()).toEqual([
      expect.objectContaining({
        to: 'pg-alice@example.com',
        text: 'Your sign-in code is 111111.',
      }),
      expect.objectContaining({
        to: 'pg-alice@example.com',
        text: 'Your sign-in code is 222222.',
      }),
    ])
    await expect(
      service.finishOtpSignIn({
        verificationId: started.verificationId,
        secret: '111111',
        channel: OtpChannel.Email,
        now,
      }),
    ).rejects.toMatchObject({
      code: UniAuthErrorCode.VerificationExpired,
    })
  })
})

function extractLinkToken(messageText: string): string {
  const match = /token=([^&\s]+)/u.exec(messageText)

  if (!match?.[1]) {
    throw new Error('Expected a token query parameter in the delivered link.')
  }

  return match[1]
}
