import { describe, expect, it } from 'vitest'
import {
  AuditEventType,
  OtpChannel,
  RateLimitAction,
  UniAuthErrorCode,
  VerificationPurpose,
  VerificationStatus,
} from '../src'
import { InMemoryRateLimiter, createInMemoryAuthKit } from '../src/testing'
import { assertion, now, rateLimitKey } from './helpers.js'

describe('rate-limit integration', () => {
  it('builds unambiguous keys for arbitrary rate-limit parts', () => {
    expect(rateLimitKey('a', 'b\u0000c')).not.toBe(rateLimitKey('a\u0000b', 'c'))
  })

  it('denies provider sign-in before creating a user, identity, or session', async () => {
    const rateLimiter = new InMemoryRateLimiter()
    rateLimiter.setDecision(
      {
        action: RateLimitAction.ProviderSignIn,
        key: rateLimitKey('email', 'alice'),
      },
      { allowed: false, retryAfterSeconds: 30 },
    )
    const { service, store } = createInMemoryAuthKit({ rateLimiter })

    const error = await service
      .signIn({ assertion: assertion({ email: 'Alice@Example.com', emailVerified: true }), now })
      .catch((caught: unknown) => caught)

    expect(error).toMatchObject({
      code: UniAuthErrorCode.RateLimited,
      message: 'Too many auth attempts.',
      details: {
        action: RateLimitAction.ProviderSignIn,
        retryAfterSeconds: 30,
      },
    })
    expect(store.listUsers()).toHaveLength(0)
    expect(store.listIdentities()).toHaveLength(0)
    expect(store.listSessions()).toHaveLength(0)
    expect(store.listAuditEvents()).toEqual([
      expect.objectContaining({
        type: AuditEventType.RateLimited,
        metadata: {
          action: RateLimitAction.ProviderSignIn,
          retryAfterSeconds: 30,
        },
      }),
    ])
    expect(rateLimiter.listAttempts()).toEqual([
      expect.objectContaining({
        action: RateLimitAction.ProviderSignIn,
        key: rateLimitKey('email', 'alice'),
      }),
    ])
  })

  it('denies OTP start before creating a verification or sending a message', async () => {
    const rateLimiter = new InMemoryRateLimiter()
    rateLimiter.setDecision(
      {
        action: RateLimitAction.OtpStart,
        key: rateLimitKey(OtpChannel.Email, 'alice@example.com'),
      },
      { allowed: false, resetAt: now },
    )
    const { service, store, emailSender } = createInMemoryAuthKit({ rateLimiter })

    const error = await service
      .startOtpChallenge({
        purpose: VerificationPurpose.SignIn,
        channel: OtpChannel.Email,
        target: ' Alice@Example.com ',
        secret: '123456',
        now,
      })
      .catch((caught: unknown) => caught)

    expect(error).toMatchObject({
      code: UniAuthErrorCode.RateLimited,
      message: 'Too many auth attempts.',
      details: {
        action: RateLimitAction.OtpStart,
        resetAt: now.toISOString(),
      },
    })
    expect(store.listVerifications()).toHaveLength(0)
    expect(emailSender.listMessages()).toHaveLength(0)
    expect(store.listAuditEvents()).toEqual([
      expect.objectContaining({
        type: AuditEventType.RateLimited,
        metadata: {
          action: RateLimitAction.OtpStart,
          resetAt: now.toISOString(),
        },
      }),
    ])
  })

  it('denies OTP finish before consuming a verification or creating a session', async () => {
    const rateLimiter = new InMemoryRateLimiter()
    const { service, store } = createInMemoryAuthKit({ rateLimiter })
    const started = await service.startOtpChallenge({
      purpose: VerificationPurpose.SignIn,
      channel: OtpChannel.Email,
      target: 'alice@example.com',
      secret: '123456',
      now,
    })
    rateLimiter.setDecision(
      {
        action: RateLimitAction.OtpFinish,
        key: rateLimitKey(OtpChannel.Email, started.verificationId),
      },
      { allowed: false, retryAfterSeconds: 15 },
    )

    const error = await service
      .finishOtpSignIn({
        verificationId: started.verificationId,
        secret: '123456',
        channel: OtpChannel.Email,
        now,
      })
      .catch((caught: unknown) => caught)

    expect(error).toMatchObject({
      code: UniAuthErrorCode.RateLimited,
      details: {
        action: RateLimitAction.OtpFinish,
        retryAfterSeconds: 15,
      },
    })
    expect(store.listVerifications()).toEqual([
      expect.objectContaining({
        id: started.verificationId,
        status: VerificationStatus.Pending,
      }),
    ])
    expect(store.listSessions()).toHaveLength(0)
    expect(rateLimiter.listAttempts()).toEqual([
      expect.objectContaining({
        action: RateLimitAction.OtpStart,
        key: rateLimitKey(OtpChannel.Email, 'alice@example.com'),
      }),
      expect.objectContaining({
        action: RateLimitAction.OtpFinish,
        key: rateLimitKey(OtpChannel.Email, started.verificationId),
      }),
    ])
  })

  it('rejects malformed rate-limit decisions before writing audit metadata', async () => {
    const invalidRetryAfterLimiter = new InMemoryRateLimiter()
    invalidRetryAfterLimiter.setDecision(
      {
        action: RateLimitAction.ProviderSignIn,
        key: rateLimitKey('email', 'alice'),
      },
      { allowed: false, retryAfterSeconds: -1 },
    )
    const invalidRetryAfterKit = createInMemoryAuthKit({
      rateLimiter: invalidRetryAfterLimiter,
    })

    await expect(
      invalidRetryAfterKit.service.signIn({
        assertion: assertion({ email: 'invalid-retry@example.com', emailVerified: true }),
        now,
      }),
    ).rejects.toMatchObject({
      code: UniAuthErrorCode.InvalidInput,
      message: 'Rate-limit retryAfterSeconds must be a non-negative number.',
    })
    expect(invalidRetryAfterKit.store.listAuditEvents()).toHaveLength(0)

    const invalidResetAtLimiter = new InMemoryRateLimiter()
    invalidResetAtLimiter.setDecision(
      {
        action: RateLimitAction.ProviderSignIn,
        key: rateLimitKey('email', 'alice'),
      },
      { allowed: false, resetAt: new Date('invalid') },
    )
    const invalidResetAtKit = createInMemoryAuthKit({ rateLimiter: invalidResetAtLimiter })

    await expect(
      invalidResetAtKit.service.signIn({
        assertion: assertion({ email: 'invalid-reset-at@example.com', emailVerified: true }),
        now,
      }),
    ).rejects.toMatchObject({
      code: UniAuthErrorCode.InvalidInput,
      message: 'Rate-limit resetAt must be a valid date.',
    })
    expect(invalidResetAtKit.store.listAuditEvents()).toHaveLength(0)
  })
})
