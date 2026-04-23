import { describe, expect, it } from 'vitest'
import { EMAIL_OTP_PROVIDER_ID, OtpChannel, UniAuthErrorCode, VerificationPurpose } from '../src'
import { createInMemoryAuthKit } from '../src/testing'
import { now } from './helpers.js'

describe('OTP configuration', () => {
  it('supports configured numeric lengths and email OTP subjects', async () => {
    const configured = createInMemoryAuthKit({
      emailOtpSubject: 'Custom sign-in code',
      otpSecretLength: 4,
    })
    const challenge = await configured.service.startOtpChallenge({
      purpose: VerificationPurpose.SignIn,
      channel: OtpChannel.Email,
      target: 'four@example.com',
      now,
    })
    const message = configured.emailSender.listMessages()[0]
    const secret = message?.text.match(/\d{4}/)?.[0]

    if (!secret) {
      throw new Error('Expected generated 4-digit OTP secret in the email message.')
    }

    expect(message?.subject).toBe('Custom sign-in code')
    await expect(
      configured.service.finishOtpSignIn({
        verificationId: challenge.verificationId,
        secret,
        channel: OtpChannel.Email,
        now,
      }),
    ).resolves.toMatchObject({
      identity: {
        provider: EMAIL_OTP_PROVIDER_ID,
        providerUserId: 'four@example.com',
      },
    })

    const eightDigit = createInMemoryAuthKit({ otpSecretLength: 8 })
    await eightDigit.service.startOtpChallenge({
      purpose: VerificationPurpose.SignIn,
      channel: OtpChannel.Phone,
      target: '+15551234567',
      now,
    })

    expect(eightDigit.smsSender.listMessages()[0]?.text).toMatch(/\d{8}/)
  })

  it('uses custom generators while preserving explicit per-request secret precedence', async () => {
    const custom = createInMemoryAuthKit({
      otpSecretGenerator: ({ channel, target }) => `${channel}:${target}:code`,
    })
    const customChallenge = await custom.service.startOtpChallenge({
      purpose: VerificationPurpose.SignIn,
      channel: OtpChannel.Email,
      target: 'custom@example.com',
      now,
    })

    expect(custom.emailSender.listMessages()[0]?.text).toContain('email:custom@example.com:code')
    await custom.service.finishOtpSignIn({
      verificationId: customChallenge.verificationId,
      secret: 'email:custom@example.com:code',
      channel: OtpChannel.Email,
      now,
    })

    const explicitSecret = createInMemoryAuthKit({
      otpSecretGenerator: () => '',
    })
    await explicitSecret.service.startOtpChallenge({
      purpose: VerificationPurpose.SignIn,
      channel: OtpChannel.Email,
      target: 'explicit@example.com',
      secret: 'explicit-secret',
      now,
    })

    expect(explicitSecret.emailSender.listMessages()[0]?.text).toContain('explicit-secret')
  })

  it('rejects invalid built-in lengths and empty custom generator output before persistence', async () => {
    const invalidLength = createInMemoryAuthKit({ otpSecretLength: 3 })
    const invalidLengthError = await invalidLength.service
      .startOtpChallenge({
        purpose: VerificationPurpose.SignIn,
        channel: OtpChannel.Email,
        target: 'invalid@example.com',
        now,
      })
      .catch((caught: unknown) => caught)
    const emptyCustom = createInMemoryAuthKit({ otpSecretGenerator: () => '' })
    const emptyCustomError = await emptyCustom.service
      .startOtpChallenge({
        purpose: VerificationPurpose.SignIn,
        channel: OtpChannel.Email,
        target: 'empty@example.com',
        now,
      })
      .catch((caught: unknown) => caught)

    expect(invalidLengthError).toMatchObject({ code: UniAuthErrorCode.InvalidInput })
    expect(emptyCustomError).toMatchObject({ code: UniAuthErrorCode.InvalidInput })
    expect(invalidLength.store.listVerifications()).toHaveLength(0)
    expect(emptyCustom.store.listVerifications()).toHaveLength(0)
  })
})
