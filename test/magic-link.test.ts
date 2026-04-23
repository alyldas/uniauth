import { describe, expect, it } from 'vitest'
import {
  AuditEventType,
  DefaultAuthService,
  EMAIL_MAGIC_LINK_PROVIDER_ID,
  OtpChannel,
  RateLimitAction,
  SessionStatus,
  UniAuthErrorCode,
  VerificationPurpose,
  VerificationStatus,
  addSeconds,
  asVerificationId,
  type EmailSender,
} from '../src'
import { InMemoryAuthStore, InMemoryRateLimiter, createInMemoryAuthKit } from '../src/testing'
import { now, rateLimitKey } from './helpers.js'

describe('email magic link sign-in', () => {
  it('starts a neutral email magic-link challenge without storing the secret plaintext', async () => {
    const { service, store, emailSender } = createInMemoryAuthKit({
      clock: { now: () => now },
    })
    const createdLinks: string[] = []

    const started = await service.startEmailMagicLinkSignIn({
      email: ' Alice@Example.com ',
      ttlSeconds: 300,
      createLink: ({ verificationId, secret, email }) => {
        const link = `https://app.example.test/auth/magic?vid=${verificationId}&token=${secret}&email=${email}`
        createdLinks.push(link)
        return link
      },
    })

    expect(started.delivery).toBe(OtpChannel.Email)
    expect(started.expiresAt).toEqual(addSeconds(now, 300))
    expect(store.listVerifications()).toEqual([
      expect.objectContaining({
        id: started.verificationId,
        purpose: VerificationPurpose.SignIn,
        target: 'alice@example.com',
        provider: EMAIL_MAGIC_LINK_PROVIDER_ID,
        channel: OtpChannel.Email,
        status: VerificationStatus.Pending,
      }),
    ])
    expect(store.listVerifications()[0]?.secretHash).not.toContain(
      createdLinks[0]?.split('token=')[1] ?? '',
    )
    expect(emailSender.listMessages()).toEqual([
      expect.objectContaining({
        to: 'alice@example.com',
        subject: 'Your sign-in link',
        text: `Sign in using this link: ${createdLinks[0]}`,
        metadata: {
          verificationId: started.verificationId,
          purpose: VerificationPurpose.SignIn,
          delivery: OtpChannel.Email,
          provider: EMAIL_MAGIC_LINK_PROVIDER_ID,
        },
      }),
    ])
  })

  it('keeps pending magic-link verifications when link creation or delivery fails', async () => {
    const linkKit = createInMemoryAuthKit()
    const linkError = await linkKit.service
      .startEmailMagicLinkSignIn({
        email: 'alice@example.com',
        secret: 'magic-secret',
        createLink: () => {
          throw new Error('Link failed.')
        },
        now,
      })
      .catch((caught: unknown) => caught)

    expect(linkError).toBeInstanceOf(Error)
    expect(linkKit.emailSender.listMessages()).toHaveLength(0)
    expect(linkKit.store.listVerifications()).toEqual([
      expect.objectContaining({
        purpose: VerificationPurpose.SignIn,
        target: 'alice@example.com',
        provider: EMAIL_MAGIC_LINK_PROVIDER_ID,
        channel: OtpChannel.Email,
        status: VerificationStatus.Pending,
      }),
    ])

    const deliveryStore = new InMemoryAuthStore()
    const failingEmailSender: EmailSender = {
      sendEmail: async () => {
        throw new Error('Delivery failed.')
      },
    }
    const deliveryService = new DefaultAuthService({
      repos: deliveryStore,
      emailSender: failingEmailSender,
    })
    const deliveryError = await deliveryService
      .startEmailMagicLinkSignIn({
        email: 'bob@example.com',
        secret: 'magic-secret',
        createLink: ({ secret }) => `https://app.example.test/auth/magic?token=${secret}`,
        now,
      })
      .catch((caught: unknown) => caught)

    expect(deliveryError).toBeInstanceOf(Error)
    expect(deliveryStore.listVerifications()).toEqual([
      expect.objectContaining({
        purpose: VerificationPurpose.SignIn,
        target: 'bob@example.com',
        provider: EMAIL_MAGIC_LINK_PROVIDER_ID,
        channel: OtpChannel.Email,
        status: VerificationStatus.Pending,
      }),
    ])
  })

  it('finishes a magic link once and creates a local session', async () => {
    const { service, store } = createInMemoryAuthKit({
      clock: { now: () => now },
    })
    const started = await service.startEmailMagicLinkSignIn({
      email: 'alice@example.com',
      secret: 'magic-secret',
      createLink: ({ secret }) => `https://app.example.test/auth/magic?token=${secret}`,
    })

    const result = await service.finishEmailMagicLinkSignIn({
      verificationId: started.verificationId,
      secret: 'magic-secret',
      sessionExpiresAt: addSeconds(now, 60),
      metadata: { flow: 'magic-link' },
    })

    expect(result.isNewUser).toBe(true)
    expect(result.identity.provider).toBe(EMAIL_MAGIC_LINK_PROVIDER_ID)
    expect(result.identity.providerUserId).toBe('alice@example.com')
    expect(result.identity.emailVerified).toBe(true)
    expect(result.session.status).toBe(SessionStatus.Active)
    expect(result.session.expiresAt).toEqual(addSeconds(now, 60))
    expect(store.listVerifications()).toEqual([
      expect.objectContaining({
        id: started.verificationId,
        status: VerificationStatus.Consumed,
      }),
    ])
    expect(store.listAuditEvents().map((event) => event.type)).toContain(AuditEventType.SignIn)

    const consumedAgainError = await service
      .finishEmailMagicLinkSignIn({
        verificationId: started.verificationId,
        secret: 'magic-secret',
      })
      .catch((caught: unknown) => caught)

    expect(consumedAgainError).toMatchObject({
      code: UniAuthErrorCode.VerificationConsumed,
    })
  })

  it('rejects invalid magic-link inputs before changing account state', async () => {
    const { service, store } = createInMemoryAuthKit()
    const defaultService = new DefaultAuthService({ repos: new InMemoryAuthStore() })

    const blankEmailError = await service
      .startEmailMagicLinkSignIn({
        email: ' ',
        createLink: () => 'https://app.example.test/auth/magic',
        now,
      })
      .catch((caught: unknown) => caught)
    const missingSenderError = await defaultService
      .startEmailMagicLinkSignIn({
        email: 'alice@example.com',
        createLink: () => 'https://app.example.test/auth/magic',
        now,
      })
      .catch((caught: unknown) => caught)
    const missingVerificationError = await service
      .finishEmailMagicLinkSignIn({
        verificationId: asVerificationId('missing'),
        secret: 'magic-secret',
        now,
      })
      .catch((caught: unknown) => caught)
    const otp = await service.startOtpChallenge({
      purpose: VerificationPurpose.SignIn,
      channel: OtpChannel.Email,
      target: 'alice@example.com',
      secret: '123456',
      now,
    })
    const otpAsMagicLinkError = await service
      .finishEmailMagicLinkSignIn({
        verificationId: otp.verificationId,
        secret: '123456',
        now,
      })
      .catch((caught: unknown) => caught)

    expect(blankEmailError).toMatchObject({ code: UniAuthErrorCode.InvalidInput })
    expect(missingSenderError).toMatchObject({ code: UniAuthErrorCode.InvalidInput })
    expect(missingVerificationError).toMatchObject({
      code: UniAuthErrorCode.VerificationNotFound,
    })
    expect(otpAsMagicLinkError).toMatchObject({ code: UniAuthErrorCode.InvalidInput })
    expect(store.listUsers()).toHaveLength(0)
    expect(store.listSessions()).toHaveLength(0)
    expect(store.listVerifications()).toHaveLength(1)
  })

  it('rate-limits magic-link start and finish without leaking account state', async () => {
    const startLimiter = new InMemoryRateLimiter()
    startLimiter.setDecision(
      {
        action: RateLimitAction.MagicLinkStart,
        key: rateLimitKey(OtpChannel.Email, 'alice@example.com'),
      },
      { allowed: false, retryAfterSeconds: 60 },
    )
    const startKit = createInMemoryAuthKit({ rateLimiter: startLimiter })
    const startError = await startKit.service
      .startEmailMagicLinkSignIn({
        email: 'alice@example.com',
        createLink: () => 'https://app.example.test/auth/magic',
        now,
      })
      .catch((caught: unknown) => caught)

    expect(startError).toMatchObject({
      code: UniAuthErrorCode.RateLimited,
      details: {
        action: RateLimitAction.MagicLinkStart,
        retryAfterSeconds: 60,
      },
    })
    expect(startKit.store.listVerifications()).toHaveLength(0)
    expect(startKit.emailSender.listMessages()).toHaveLength(0)

    const finishLimiter = new InMemoryRateLimiter()
    const finishKit = createInMemoryAuthKit({ rateLimiter: finishLimiter })
    const started = await finishKit.service.startEmailMagicLinkSignIn({
      email: 'alice@example.com',
      secret: 'magic-secret',
      createLink: ({ secret }) => `https://app.example.test/auth/magic?token=${secret}`,
      now,
    })
    finishLimiter.setDecision(
      {
        action: RateLimitAction.MagicLinkFinish,
        key: rateLimitKey(OtpChannel.Email, started.verificationId),
      },
      { allowed: false, resetAt: now },
    )
    const finishError = await finishKit.service
      .finishEmailMagicLinkSignIn({
        verificationId: started.verificationId,
        secret: 'magic-secret',
        now,
      })
      .catch((caught: unknown) => caught)

    expect(finishError).toMatchObject({
      code: UniAuthErrorCode.RateLimited,
      details: {
        action: RateLimitAction.MagicLinkFinish,
        resetAt: now.toISOString(),
      },
    })
    expect(finishKit.store.listVerifications()).toEqual([
      expect.objectContaining({
        id: started.verificationId,
        status: VerificationStatus.Pending,
      }),
    ])
    expect(finishKit.store.listUsers()).toHaveLength(0)
    expect(finishKit.store.listSessions()).toHaveLength(0)
  })
})
