import { describe, expect, it } from 'vitest'
import { OtpChannel, UniAuthErrorCode, VerificationPurpose, createDefaultAuthPolicy } from '../src'
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

  it('rejects invalid phone and generic verification targets before persistence or delivery', async () => {
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
})
