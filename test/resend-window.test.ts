import { describe, expect, it } from 'vitest'
import {
  OtpChannel,
  RateLimitAction,
  UniAuthError,
  UniAuthErrorCode,
  VerificationPurpose,
  VerificationStatus,
  addSeconds,
  getRateLimitedErrorDetails,
  isRateLimitedErrorDetails,
} from '../src'
import { InMemoryRateLimiter, createInMemoryAuthKit } from '../src/testing'
import { assertion, now, rateLimitKey } from './helpers.js'
import { createPostgresTestKit } from './postgres/support.js'

describe('verification resend window and rate-limit helpers', () => {
  it('computes resend window state for pending, consumed, and expired in-memory verifications', async () => {
    const { service } = createInMemoryAuthKit({
      verificationResendCooldownSeconds: 60,
    })
    const started = await service.startOtpChallenge({
      purpose: VerificationPurpose.SignIn,
      channel: OtpChannel.Email,
      target: 'alice@example.com',
      secret: '123456',
      ttlSeconds: 300,
      now,
    })

    expect(
      await service.getVerificationResendWindow({
        verificationId: started.verificationId,
        now: addSeconds(now, 30),
      }),
    ).toMatchObject({
      id: started.verificationId,
      purpose: VerificationPurpose.SignIn,
      status: VerificationStatus.Pending,
      provider: 'email-otp',
      channel: OtpChannel.Email,
      resendAllowed: false,
      expired: false,
      resendAvailableAt: addSeconds(now, 60),
      cooldownSeconds: 60,
      cooldownRemainingSeconds: 30,
    })
    expect(
      await service.getVerificationResendWindow({
        verificationId: started.verificationId,
        now: addSeconds(now, 60),
      }),
    ).toMatchObject({
      resendAllowed: true,
      cooldownRemainingSeconds: 0,
    })

    await service.finishOtpChallenge({
      verificationId: started.verificationId,
      secret: '123456',
      channel: OtpChannel.Email,
      now: addSeconds(now, 61),
    })

    expect(
      await service.getVerificationResendWindow({
        verificationId: started.verificationId,
        now: addSeconds(now, 61),
      }),
    ).toMatchObject({
      status: VerificationStatus.Consumed,
      resendAllowed: false,
      expired: false,
      cooldownRemainingSeconds: 0,
      consumedAt: addSeconds(now, 61),
    })

    const expired = await service.startOtpChallenge({
      purpose: VerificationPurpose.SignIn,
      channel: OtpChannel.Email,
      target: 'bob@example.com',
      secret: '654321',
      ttlSeconds: 30,
      now,
    })

    expect(
      await service.getVerificationResendWindow({
        verificationId: expired.verificationId,
        now: addSeconds(now, 31),
      }),
    ).toMatchObject({
      status: VerificationStatus.Pending,
      resendAllowed: false,
      expired: true,
      cooldownRemainingSeconds: 29,
    })
  })

  it('supports a per-call cooldown override for resend window reads', async () => {
    const { service } = createInMemoryAuthKit({
      clock: { now: () => now },
      verificationResendCooldownSeconds: 90,
    })
    const created = await service.createVerification({
      purpose: VerificationPurpose.Link,
      target: 'opaque-target',
      secret: 'secret-token',
      now,
    })

    expect(
      await service.getVerificationResendWindow({
        verificationId: created.verification.id,
        cooldownSeconds: 15,
        now: addSeconds(now, 15),
      }),
    ).toMatchObject({
      resendAllowed: true,
      cooldownSeconds: 15,
      cooldownRemainingSeconds: 0,
    })
    expect(
      await service.getVerificationResendWindow({
        verificationId: created.verification.id,
      }),
    ).toMatchObject({
      resendAllowed: false,
      cooldownSeconds: 90,
      cooldownRemainingSeconds: 90,
    })
  })

  it('rejects invalid resend cooldown input', async () => {
    const { service } = createInMemoryAuthKit()
    const created = await service.createVerification({
      purpose: VerificationPurpose.Link,
      target: 'opaque-target',
      secret: 'secret-token',
      now,
    })

    await expect(
      service.getVerificationResendWindow({
        verificationId: created.verification.id,
        cooldownSeconds: -1,
        now,
      }),
    ).rejects.toMatchObject({
      code: UniAuthErrorCode.InvalidInput,
      message: 'Verification resend cooldown must be a non-negative integer.',
    })
    await expect(
      service.getVerificationResendWindow({
        verificationId: created.verification.id,
        cooldownSeconds: Number.MAX_VALUE,
        now,
      }),
    ).rejects.toMatchObject({
      code: UniAuthErrorCode.InvalidInput,
      message: 'Verification resend cooldown produces an invalid availability time.',
    })
    const overflowRuntime = createInMemoryAuthKit({
      verificationResendCooldownSeconds: Number.MAX_VALUE,
    })
    const overflowRuntimeVerification = await overflowRuntime.service.createVerification({
      purpose: VerificationPurpose.Link,
      target: 'runtime-overflow-target',
      secret: 'secret-token',
      now,
    })

    await expect(
      overflowRuntime.service.getVerificationResendWindow({
        verificationId: overflowRuntimeVerification.verification.id,
        now,
      }),
    ).rejects.toMatchObject({
      code: UniAuthErrorCode.InvalidInput,
      message: 'Verification resend cooldown produces an invalid availability time.',
    })
  })

  it('keeps Postgres resend window semantics aligned with in-memory behavior', async () => {
    const { service } = await createPostgresTestKit({
      verificationResendCooldownSeconds: 60,
    })
    const started = await service.startOtpChallenge({
      purpose: VerificationPurpose.SignIn,
      channel: OtpChannel.Email,
      target: 'pg-alice@example.com',
      secret: '123456',
      ttlSeconds: 300,
      now,
    })

    expect(
      await service.getVerificationResendWindow({
        verificationId: started.verificationId,
        now: addSeconds(now, 30),
      }),
    ).toMatchObject({
      status: VerificationStatus.Pending,
      resendAllowed: false,
      expired: false,
      resendAvailableAt: addSeconds(now, 60),
      cooldownRemainingSeconds: 30,
    })
  })

  it('extracts typed rate-limit error details from real service failures', async () => {
    const rateLimiter = new InMemoryRateLimiter()
    const { service } = createInMemoryAuthKit({ rateLimiter })
    rateLimiter.setDecision(
      {
        action: RateLimitAction.ProviderSignIn,
        key: rateLimitKey('email', 'alice'),
      },
      { allowed: false, retryAfterSeconds: 45 },
    )

    const error = await service
      .signIn({ assertion: assertion({ email: 'alice@example.com', emailVerified: true }), now })
      .catch((caught: unknown) => caught)

    expect(getRateLimitedErrorDetails(error)).toEqual({
      action: RateLimitAction.ProviderSignIn,
      retryAfterSeconds: 45,
    })
    expect(
      getRateLimitedErrorDetails(
        new UniAuthError(UniAuthErrorCode.InvalidInput, 'Invalid auth input.'),
      ),
    ).toBeUndefined()
    expect(
      getRateLimitedErrorDetails(
        new UniAuthError(UniAuthErrorCode.RateLimited, 'Too many auth attempts.', { action: '' }),
      ),
    ).toBeUndefined()
    expect(isRateLimitedErrorDetails('nope')).toBe(false)
    expect(isRateLimitedErrorDetails({ action: '' })).toBe(false)
    expect(
      isRateLimitedErrorDetails({
        action: RateLimitAction.OtpStart,
        retryAfterSeconds: -1,
      }),
    ).toBe(false)
    expect(
      isRateLimitedErrorDetails({
        action: RateLimitAction.OtpStart,
        resetAt: 123,
      }),
    ).toBe(false)
    expect(
      isRateLimitedErrorDetails({
        action: RateLimitAction.OtpStart,
        resetAt: 'not-a-date',
      }),
    ).toBe(false)
    expect(
      isRateLimitedErrorDetails({
        action: RateLimitAction.OtpStart,
        retryAfterSeconds: 15,
        resetAt: now.toISOString(),
      }),
    ).toBe(true)
    expect(isRateLimitedErrorDetails(null)).toBe(false)
  })
})
