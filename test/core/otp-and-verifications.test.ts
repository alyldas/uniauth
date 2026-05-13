import { describe, expect, it } from 'vitest'
import {
  DefaultAuthService,
  EMAIL_OTP_PROVIDER_ID,
  OtpChannel,
  PHONE_OTP_PROVIDER_ID,
  SessionStatus,
  UniAuthErrorCode,
  VerificationPurpose,
  VerificationStatus,
  addSeconds,
  asVerificationId,
  createHmacSecretHasher,
  type EmailSender,
} from '../../src'
import { InMemoryAuthStore, createInMemoryAuthKit } from '../../src/testing'
import { now } from './support.js'

describe('DefaultAuthService OTP and verification flows', () => {
  it('stores verification secrets only as hashes and consumes valid secrets once', async () => {
    const { service, store } = createInMemoryAuthKit()

    const created = await service.createVerification({
      purpose: VerificationPurpose.SignIn,
      target: 'Alice@Example.com',
      secret: '123456',
      now,
    })

    expect(created.secret).toBe('123456')
    expect(created.verification.target).toBe('alice@example.com')
    expect(created.verification.secretHash).not.toBe('123456')
    expect(created.verification.secretHash).toMatch(/^scrypt:/)
    expect(store.listVerifications()[0]?.secretHash).toBe(created.verification.secretHash)

    const invalidSecretError = await service
      .consumeVerification({
        verificationId: created.verification.id,
        secret: 'wrong',
        now,
      })
      .catch((caught: unknown) => caught)

    expect(invalidSecretError).toMatchObject({
      code: UniAuthErrorCode.VerificationInvalidSecret,
    })

    await expect(
      service.consumeVerification({
        verificationId: created.verification.id,
        secret: '   ',
        now,
      }),
    ).rejects.toMatchObject({ code: UniAuthErrorCode.InvalidInput })

    const consumed = await service.consumeVerification({
      verificationId: created.verification.id,
      secret: '123456',
      now,
    })

    expect(consumed.status).toBe(VerificationStatus.Consumed)
    const consumedAgainError = await service
      .consumeVerification({
        verificationId: created.verification.id,
        secret: '123456',
        now,
      })
      .catch((caught: unknown) => caught)

    expect(consumedAgainError).toMatchObject({
      code: UniAuthErrorCode.VerificationConsumed,
    })

    const blankTargetError = await service
      .createVerification({
        purpose: VerificationPurpose.SignIn,
        target: '   ',
        secret: '123456',
        now,
      })
      .catch((caught: unknown) => caught)

    expect(blankTargetError).toMatchObject({ code: UniAuthErrorCode.InvalidInput })
    expect(store.listVerifications()).toHaveLength(1)

    await expect(
      service.createVerification({
        purpose: VerificationPurpose.SignIn,
        target: 'blank-secret@example.com',
        secret: '   ',
        now,
      }),
    ).rejects.toMatchObject({ code: UniAuthErrorCode.InvalidInput })
    expect(store.listVerifications()).toHaveLength(1)

    await expect(
      service.createVerification({
        purpose: VerificationPurpose.SignIn,
        target: 'metadata-array@example.com',
        secret: '123456',
        metadata: ['not-a-record'],
        now,
      } as unknown as Parameters<typeof service.createVerification>[0]),
    ).rejects.toMatchObject({
      code: UniAuthErrorCode.InvalidInput,
    })

    const nullPrototypeMetadata = Object.assign(Object.create(null) as Record<string, unknown>, {
      requestId: 'req-null-prototype',
    })
    await expect(
      service.createVerification({
        purpose: VerificationPurpose.SignIn,
        target: 'metadata-record@example.com',
        secret: '123456',
        metadata: nullPrototypeMetadata,
        now,
      }),
    ).resolves.toMatchObject({
      verification: {
        metadata: { requestId: 'req-null-prototype' },
      },
    })
  })

  it('uses a configured secret hasher for verification storage', async () => {
    const { service, store } = createInMemoryAuthKit({
      secretHasher: createHmacSecretHasher({ pepper: 'test-pepper' }),
    })

    const created = await service.createVerification({
      purpose: VerificationPurpose.SignIn,
      target: 'Alice@Example.com',
      secret: '123456',
      now,
    })

    expect(created.verification.secretHash).toMatch(/^hmac-sha256:/)
    expect(store.listVerifications()[0]?.secretHash).toBe(created.verification.secretHash)

    const consumed = await service.consumeVerification({
      verificationId: created.verification.id,
      secret: '123456',
      now,
    })

    expect(consumed.status).toBe(VerificationStatus.Consumed)
  })

  it('starts and finishes email OTP sign-in without exposing account state', async () => {
    const { emailSender, service, store } = createInMemoryAuthKit()

    const started = await service.startOtpChallenge({
      purpose: VerificationPurpose.SignIn,
      channel: OtpChannel.Email,
      target: ' Alice@Example.com ',
      secret: '123456',
      metadata: { requestId: 'req-1' },
      now,
    })

    expect(started).toEqual({
      verificationId: started.verificationId,
      expiresAt: new Date('2026-01-01T00:10:00.000Z'),
      delivery: 'email',
    })
    expect(started).not.toHaveProperty('isNewUser')
    expect(started).not.toHaveProperty('user')

    const [message] = emailSender.listMessages()
    const [storedVerification] = store.listVerifications()

    expect(message).toMatchObject({
      to: 'alice@example.com',
      subject: 'Your sign-in code',
      text: 'Your sign-in code is 123456.',
    })
    expect(message?.metadata).toMatchObject({
      verificationId: started.verificationId,
      purpose: VerificationPurpose.SignIn,
      delivery: 'email',
    })
    expect(storedVerification).toMatchObject({
      id: started.verificationId,
      purpose: VerificationPurpose.SignIn,
      target: 'alice@example.com',
      provider: EMAIL_OTP_PROVIDER_ID,
      channel: OtpChannel.Email,
      status: VerificationStatus.Pending,
      metadata: {
        requestId: 'req-1',
      },
    })
    expect(storedVerification?.secretHash).not.toBe('123456')
    expect(storedVerification?.secretHash).toMatch(/^scrypt:/)

    const wrongSecret = await service
      .finishOtpSignIn({
        verificationId: started.verificationId,
        secret: '000000',
        channel: OtpChannel.Email,
        now,
      })
      .catch((caught: unknown) => caught)

    expect(wrongSecret).toMatchObject({
      code: UniAuthErrorCode.VerificationInvalidSecret,
    })
    expect(store.listVerifications()[0]?.status).toBe(VerificationStatus.Pending)

    const finished = await service.finishOtpSignIn({
      verificationId: started.verificationId,
      secret: '123456',
      channel: OtpChannel.Email,
      metadata: { flow: 'otp' },
      now,
    })

    expect(finished.isNewUser).toBe(true)
    expect(finished.identity.provider).toBe(EMAIL_OTP_PROVIDER_ID)
    expect(finished.identity.providerUserId).toBe('alice@example.com')
    expect(finished.identity.email).toBe('alice@example.com')
    expect(finished.session.status).toBe(SessionStatus.Active)
    expect(store.listVerifications()[0]?.status).toBe(VerificationStatus.Consumed)

    const consumedAgain = await service
      .finishOtpSignIn({
        verificationId: started.verificationId,
        secret: '123456',
        channel: OtpChannel.Email,
        now,
      })
      .catch((caught: unknown) => caught)

    expect(consumedAgain).toMatchObject({
      code: UniAuthErrorCode.VerificationConsumed,
    })

    const generated = await service.startOtpChallenge({
      purpose: VerificationPurpose.SignIn,
      channel: OtpChannel.Email,
      target: 'bob@example.com',
      ttlSeconds: 30,
      now,
    })
    const generatedMessage = emailSender.listMessages()[1]
    const generatedSecret = generatedMessage?.text.match(/\d{6}/)?.[0]

    if (!generatedSecret) {
      throw new Error('Expected generated OTP secret in the email message.')
    }

    const generatedFinished = await service.finishOtpSignIn({
      verificationId: generated.verificationId,
      secret: generatedSecret,
      channel: OtpChannel.Email,
      sessionExpiresAt: addSeconds(now, 60),
      now,
    })

    expect(generated.delivery).toBe('email')
    expect(generatedFinished.session.expiresAt).toEqual(addSeconds(now, 60))
  })

  it('allows only one concurrent OTP sign-in to consume a verification', async () => {
    const { service, store } = createInMemoryAuthKit()
    const started = await service.startOtpChallenge({
      purpose: VerificationPurpose.SignIn,
      channel: OtpChannel.Email,
      target: 'race@example.com',
      secret: '123456',
      now,
    })

    const results = await Promise.allSettled([
      service.finishOtpSignIn({
        verificationId: started.verificationId,
        secret: '123456',
        channel: OtpChannel.Email,
        now,
      }),
      service.finishOtpSignIn({
        verificationId: started.verificationId,
        secret: '123456',
        channel: OtpChannel.Email,
        now,
      }),
    ])

    expect(results.filter((result) => result.status === 'fulfilled')).toHaveLength(1)
    expect(results.filter((result) => result.status === 'rejected')).toHaveLength(1)
    expect(store.listSessions()).toHaveLength(1)
    expect(store.listVerifications()[0]).toMatchObject({
      id: started.verificationId,
      status: VerificationStatus.Consumed,
    })
  })

  it('keeps a pending OTP verification when app-owned delivery fails', async () => {
    const store = new InMemoryAuthStore()
    const failingEmailSender: EmailSender = {
      sendEmail: async () => {
        throw new Error('Delivery failed.')
      },
    }
    const service = new DefaultAuthService({
      repos: store,
      emailSender: failingEmailSender,
    })

    const error = await service
      .startOtpChallenge({
        purpose: VerificationPurpose.SignIn,
        channel: OtpChannel.Email,
        target: 'delivery@example.com',
        secret: '123456',
        now,
      })
      .catch((caught: unknown) => caught)

    expect(error).toBeInstanceOf(Error)
    expect(store.listVerifications()).toHaveLength(1)
    expect(store.listVerifications()[0]).toMatchObject({
      purpose: VerificationPurpose.SignIn,
      target: 'delivery@example.com',
      provider: EMAIL_OTP_PROVIDER_ID,
      channel: OtpChannel.Email,
      status: VerificationStatus.Pending,
    })
    expect(store.listVerifications()[0]?.secretHash).not.toBe('123456')
  })

  it('reuses generic OTP challenges for email and phone sign-in channels', async () => {
    const { emailSender, service, smsSender, store } = createInMemoryAuthKit()

    const emailLinkChallenge = await service.startOtpChallenge({
      purpose: VerificationPurpose.Link,
      channel: OtpChannel.Email,
      target: ' Link@Example.com ',
      secret: '111111',
      now,
    })
    const consumedEmailLink = await service.finishOtpChallenge({
      verificationId: emailLinkChallenge.verificationId,
      secret: '111111',
      purpose: VerificationPurpose.Link,
      channel: OtpChannel.Email,
      now,
    })

    expect(emailLinkChallenge.delivery).toBe(OtpChannel.Email)
    expect(consumedEmailLink.status).toBe(VerificationStatus.Consumed)
    expect(emailSender.listMessages()[0]).toMatchObject({
      to: 'link@example.com',
      text: 'Your sign-in code is 111111.',
    })

    const clockFallbackChallenge = await service.startOtpChallenge({
      purpose: VerificationPurpose.Link,
      channel: OtpChannel.Email,
      target: 'clock@example.com',
      secret: '222222',
    })
    const clockFallbackConsumed = await service.finishOtpChallenge({
      verificationId: clockFallbackChallenge.verificationId,
      secret: '222222',
      purpose: VerificationPurpose.Link,
      channel: OtpChannel.Email,
    })

    expect(clockFallbackConsumed.status).toBe(VerificationStatus.Consumed)

    const phoneChallenge = await service.startOtpChallenge({
      purpose: VerificationPurpose.SignIn,
      channel: OtpChannel.Phone,
      target: ' +1 (555) 123-4567 ',
      secret: '654321',
      metadata: { requestId: 'req-phone' },
      now,
    })

    expect(phoneChallenge).toEqual({
      verificationId: phoneChallenge.verificationId,
      expiresAt: new Date('2026-01-01T00:10:00.000Z'),
      delivery: OtpChannel.Phone,
    })
    expect(smsSender.listMessages()[0]).toMatchObject({
      to: '+15551234567',
      text: 'Your sign-in code is 654321.',
      metadata: {
        verificationId: phoneChallenge.verificationId,
        purpose: VerificationPurpose.SignIn,
        delivery: OtpChannel.Phone,
      },
    })
    expect(store.listVerifications()[2]).toMatchObject({
      id: phoneChallenge.verificationId,
      target: '+15551234567',
      provider: PHONE_OTP_PROVIDER_ID,
      channel: OtpChannel.Phone,
      metadata: {
        requestId: 'req-phone',
      },
    })

    const phoneResult = await service.finishOtpSignIn({
      verificationId: phoneChallenge.verificationId,
      secret: '654321',
      metadata: { flow: 'phone-otp' },
      now,
    })

    expect(phoneResult.identity.provider).toBe(PHONE_OTP_PROVIDER_ID)
    expect(phoneResult.identity.providerUserId).toBe('+15551234567')
    expect(phoneResult.identity.phone).toBe('+15551234567')
    expect(phoneResult.identity.phoneVerified).toBe(true)
    expect(phoneResult.session.status).toBe(SessionStatus.Active)
  })

  it('rejects invalid email OTP sign-in starts and wrong verification purposes', async () => {
    const serviceWithoutEmailSender = new DefaultAuthService({
      repos: new InMemoryAuthStore(),
    })

    expect(
      await serviceWithoutEmailSender
        .startOtpChallenge({
          purpose: VerificationPurpose.SignIn,
          channel: OtpChannel.Email,
          target: 'alice@example.com',
          now,
        })
        .catch((caught: unknown) => caught),
    ).toMatchObject({ code: UniAuthErrorCode.InvalidInput })
    expect(
      await serviceWithoutEmailSender
        .startOtpChallenge({
          purpose: VerificationPurpose.SignIn,
          channel: OtpChannel.Email,
          target: '   ',
          now,
        })
        .catch((caught: unknown) => caught),
    ).toMatchObject({ code: UniAuthErrorCode.InvalidInput })
    expect(
      await serviceWithoutEmailSender
        .finishOtpSignIn({
          verificationId: asVerificationId('missing'),
          secret: '123456',
          channel: OtpChannel.Email,
          now,
        })
        .catch((caught: unknown) => caught),
    ).toMatchObject({ code: UniAuthErrorCode.VerificationNotFound })

    const { service, store } = createInMemoryAuthKit()
    const linkVerification = await service.createVerification({
      purpose: VerificationPurpose.Link,
      target: 'alice@example.com',
      secret: '123456',
      now,
    })
    const wrongPurpose = await service
      .finishOtpSignIn({
        verificationId: linkVerification.verification.id,
        secret: '123456',
        channel: OtpChannel.Email,
        now,
      })
      .catch((caught: unknown) => caught)

    expect(wrongPurpose).toMatchObject({ code: UniAuthErrorCode.InvalidInput })
    expect(store.listVerifications()[0]?.status).toBe(VerificationStatus.Pending)
  })

  it('rejects invalid generic OTP challenge usage without consuming secrets', async () => {
    const serviceWithoutSmsSender = new DefaultAuthService({
      repos: new InMemoryAuthStore(),
    })

    expect(
      await serviceWithoutSmsSender
        .startOtpChallenge({
          purpose: VerificationPurpose.SignIn,
          channel: OtpChannel.Phone,
          target: '+15551234567',
          now,
        })
        .catch((caught: unknown) => caught),
    ).toMatchObject({ code: UniAuthErrorCode.InvalidInput })
    expect(
      await serviceWithoutSmsSender
        .startOtpChallenge({
          purpose: VerificationPurpose.SignIn,
          // @ts-expect-error Unsupported channels are a runtime guard for untyped callers.
          channel: 'push',
          target: 'alice',
          now,
        })
        .catch((caught: unknown) => caught),
    ).toMatchObject({ code: UniAuthErrorCode.InvalidInput })
    expect(
      await serviceWithoutSmsSender
        .startOtpChallenge({
          purpose: VerificationPurpose.SignIn,
          // @ts-expect-error Unsupported channels are a runtime guard for untyped callers.
          channel: 'push',
          target: '   ',
          now,
        })
        .catch((caught: unknown) => caught),
    ).toMatchObject({ code: UniAuthErrorCode.InvalidInput })
    expect(
      await serviceWithoutSmsSender
        .startOtpChallenge({
          purpose: VerificationPurpose.SignIn,
          channel: OtpChannel.Phone,
          target: '   ',
          now,
        })
        .catch((caught: unknown) => caught),
    ).toMatchObject({ code: UniAuthErrorCode.InvalidInput })

    const { service, store } = createInMemoryAuthKit()
    const challenge = await service.startOtpChallenge({
      purpose: VerificationPurpose.SignIn,
      channel: OtpChannel.Email,
      target: 'alice@example.com',
      secret: '123456',
      now,
    })
    const wrongChannel = await service
      .finishOtpChallenge({
        verificationId: challenge.verificationId,
        secret: '123456',
        purpose: VerificationPurpose.SignIn,
        channel: OtpChannel.Phone,
        now,
      })
      .catch((caught: unknown) => caught)

    expect(wrongChannel).toMatchObject({ code: UniAuthErrorCode.InvalidInput })
    expect(store.listVerifications()[0]?.status).toBe(VerificationStatus.Pending)

    const rawVerification = await service.createVerification({
      purpose: VerificationPurpose.SignIn,
      target: 'raw@example.com',
      secret: '123456',
      now,
    })
    const notOtpChallenge = await service
      .finishOtpChallenge({
        verificationId: rawVerification.verification.id,
        secret: '123456',
        now,
      })
      .catch((caught: unknown) => caught)

    expect(notOtpChallenge).toMatchObject({ code: UniAuthErrorCode.InvalidInput })
    expect(store.listVerifications()[1]?.status).toBe(VerificationStatus.Pending)
  })
})
