import { describe, expect, it } from 'vitest'
import {
  OtpChannel,
  UniAuthErrorCode,
  VerificationPurpose,
  createAuthNormalizer,
  createDefaultAuthPolicy,
} from '../src'
import { normalizeOtpTarget } from '../src/application/otp-delivery.js'
import { createInMemoryAuthKit } from '../src/testing'
import { assertion, createStrictNormalizer, now } from './helpers.js'

describe('shared normalization boundary', () => {
  it('uses one configured normalizer across provider assertions and repository lookups', async () => {
    const normalizer = createStrictNormalizer()
    const { service, store } = createInMemoryAuthKit({
      normalizer,
      policy: createDefaultAuthPolicy({ allowAutoLink: true }),
    })

    const first = await service.signIn({
      assertion: assertion({
        provider: 'phone-first',
        providerUserId: 'phone-first-user',
        phone: '+1 (555) 123-4567',
        phoneVerified: true,
      }),
      now,
    })
    const linked = await service.signIn({
      assertion: assertion({
        provider: 'oidc',
        providerUserId: 'oidc-user',
        phone: '5551234567',
        phoneVerified: true,
      }),
      now,
    })

    expect(linked.user.id).toBe(first.user.id)
    expect(linked.isNewUser).toBe(false)
    expect(linked.isNewIdentity).toBe(true)
    expect(linked.identity.phone).toBe('+15551234567')
    await expect(store.identityRepo.findByVerifiedPhone('5551234567')).resolves.toHaveLength(2)
  })

  it('rejects invalid email before magic link and password side effects', async () => {
    const normalizer = createStrictNormalizer()
    const { service, store, emailSender } = createInMemoryAuthKit({ normalizer })

    await expect(
      service.startEmailMagicLinkSignIn({
        email: 'invalid-email',
        createLink: ({ verificationId, secret }) =>
          `/auth/magic?verification=${verificationId}&token=${secret}`,
        now,
      }),
    ).rejects.toMatchObject({
      code: UniAuthErrorCode.InvalidInput,
      message: 'Email is invalid.',
    })
    expect(store.listVerifications()).toHaveLength(0)
    expect(emailSender.listMessages()).toHaveLength(0)

    const signedIn = await service.signIn({
      assertion: assertion({
        provider: 'email',
        providerUserId: 'valid-owner',
        email: 'owner@example.com',
        emailVerified: true,
      }),
      now,
    })

    await expect(
      service.setPassword({
        userId: signedIn.user.id,
        email: 'bad',
        password: 'new-password',
        now,
      }),
    ).rejects.toMatchObject({
      code: UniAuthErrorCode.InvalidInput,
      message: 'Email is invalid.',
    })
    await expect(
      service.signInWithPassword({
        email: 'bad',
        password: 'new-password',
        now,
      }),
    ).rejects.toMatchObject({
      code: UniAuthErrorCode.InvalidInput,
      message: 'Email is invalid.',
    })
    expect(store.listCredentials()).toHaveLength(0)
  })

  it('treats blank optional provider claims as absent with a strict normalizer', async () => {
    const normalizer = createStrictNormalizer()
    const { service } = createInMemoryAuthKit({ normalizer })

    const blankProfile = await service.signIn({
      assertion: {
        provider: 'oauth',
        providerUserId: 'blank-profile',
        email: '   ',
        emailVerified: true,
        phone: '   ',
        phoneVerified: true,
        displayName: '   ',
      },
      now,
    })

    expect(blankProfile.user.email).toBeUndefined()
    expect(blankProfile.user.phone).toBeUndefined()
    expect(blankProfile.user.displayName).toBeUndefined()
    expect(blankProfile.identity.email).toBeUndefined()
    expect(blankProfile.identity.phone).toBeUndefined()
  })

  it('preserves required-input errors before strict normalization runs', async () => {
    const normalizer = createStrictNormalizer()
    const { service, store, emailSender, smsSender } = createInMemoryAuthKit({ normalizer })
    const signedIn = await service.signIn({
      assertion: assertion({
        provider: 'email',
        providerUserId: 'owner',
        email: 'owner@example.com',
        emailVerified: true,
      }),
      now,
    })

    await expect(
      service.startEmailMagicLinkSignIn({
        email: '   ',
        createLink: ({ verificationId, secret }) =>
          `/auth/magic?verification=${verificationId}&token=${secret}`,
        now,
      }),
    ).rejects.toMatchObject({
      code: UniAuthErrorCode.InvalidInput,
      message: 'Email is required.',
    })
    await expect(
      service.setPassword({
        userId: signedIn.user.id,
        email: '   ',
        password: 'new-password',
        now,
      }),
    ).rejects.toMatchObject({
      code: UniAuthErrorCode.InvalidInput,
      message: 'Email is required.',
    })
    await expect(
      service.startOtpChallenge({
        purpose: VerificationPurpose.SignIn,
        channel: OtpChannel.Phone,
        target: '   ',
        now,
      }),
    ).rejects.toMatchObject({
      code: UniAuthErrorCode.InvalidInput,
      message: 'Phone is required.',
    })
    await expect(
      service.createVerification({
        purpose: VerificationPurpose.Link,
        target: '   ',
        now,
      }),
    ).rejects.toMatchObject({
      code: UniAuthErrorCode.InvalidInput,
      message: 'Verification target is required.',
    })
    await expect(
      service.createVerification({
        purpose: VerificationPurpose.Link,
        target: 123,
        now,
      } as unknown as Parameters<typeof service.createVerification>[0]),
    ).rejects.toMatchObject({
      code: UniAuthErrorCode.InvalidInput,
      message: 'Verification target is required.',
    })

    expect(store.listVerifications()).toHaveLength(0)
    expect(emailSender.listMessages()).toHaveLength(0)
    expect(smsSender.listMessages()).toHaveLength(0)
  })

  it('maps empty normalized values back to required-input errors', async () => {
    const emptyNormalizer = createAuthNormalizer({
      normalizeEmail: () => '',
      normalizePhone: () => '',
      normalizeTarget: () => '',
    })
    const { service } = createInMemoryAuthKit({ normalizer: emptyNormalizer })
    const signedIn = await service.signIn({
      assertion: assertion({
        provider: 'owner',
        providerUserId: 'owner',
      }),
      now,
    })

    await expect(
      service.startEmailMagicLinkSignIn({
        email: 'owner@example.com',
        createLink: () => '/auth/magic',
        now,
      }),
    ).rejects.toMatchObject({
      code: UniAuthErrorCode.InvalidInput,
      message: 'Email is required.',
    })
    await expect(
      service.setPassword({
        userId: signedIn.user.id,
        email: 'owner@example.com',
        password: 'new-password',
        now,
      }),
    ).rejects.toMatchObject({
      code: UniAuthErrorCode.InvalidInput,
      message: 'Email is required.',
    })
    await expect(
      service.createVerification({
        purpose: VerificationPurpose.Link,
        target: 'opaque-token',
        now,
      }),
    ).rejects.toMatchObject({
      code: UniAuthErrorCode.InvalidInput,
      message: 'Verification target is required.',
    })
    expect(() =>
      normalizeOtpTarget({ normalizer: emptyNormalizer }, OtpChannel.Email, 'owner@example.com'),
    ).toThrow('Email is required.')
    expect(() =>
      normalizeOtpTarget({ normalizer: emptyNormalizer }, OtpChannel.Phone, '+15551234567'),
    ).toThrow('Phone is required.')
    expect(() =>
      normalizeOtpTarget({ normalizer: emptyNormalizer }, 'custom' as never, 'opaque-token'),
    ).toThrow('OTP target is required.')
  })

  it('rejects invalid phone and invalid email targets before persistence or delivery', async () => {
    const normalizer = createStrictNormalizer()
    const { service, store, smsSender } = createInMemoryAuthKit({ normalizer })

    await expect(
      service.startOtpChallenge({
        purpose: VerificationPurpose.SignIn,
        channel: OtpChannel.Phone,
        target: '123',
        now,
      }),
    ).rejects.toMatchObject({
      code: UniAuthErrorCode.InvalidInput,
      message: 'Phone is invalid.',
    })
    await expect(
      service.createVerification({
        purpose: VerificationPurpose.Link,
        target: 'invalid@',
        now,
      }),
    ).rejects.toMatchObject({
      code: UniAuthErrorCode.InvalidInput,
      message: 'Email is invalid.',
    })

    expect(store.listVerifications()).toHaveLength(0)
    expect(smsSender.listMessages()).toHaveLength(0)
  })

  it('keeps opaque verification targets generic under a strict normalizer', async () => {
    const normalizer = createStrictNormalizer()
    const { service, store } = createInMemoryAuthKit({ normalizer })

    const created = await service.createVerification({
      purpose: VerificationPurpose.Link,
      target: ' opaque-token ',
      secret: 'opaque-secret',
      now,
    })

    expect(created.verification.target).toBe('opaque-token')
    expect(store.listVerifications()[0]?.target).toBe('opaque-token')
  })
})
