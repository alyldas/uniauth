import { describe, expect, it } from 'vitest'
import {
  AuthPolicyAction,
  UniAuthErrorCode,
  VerificationPurpose,
  VerificationStatus,
  addSeconds,
  asVerificationId,
  createAuthService,
  createDefaultAuthPolicy,
  type ProviderIdentityAssertion,
} from '../src'
import { createInMemoryAuthKit, InMemoryAuthStore, StaticAuthProvider } from '../src/testing'
import { assertion, now } from './helpers.js'

describe('provider, policy, and verification edge cases', () => {
  it('covers provider resolution and assertion validation failures', async () => {
    const noRegistryService = createAuthService({ repos: new InMemoryAuthStore() })

    expect(
      await noRegistryService
        .signIn({ provider: 'missing', finishInput: {}, now })
        .catch((caught: unknown) => caught),
    ).toMatchObject({
      code: UniAuthErrorCode.ProviderNotFound,
    })
    expect(
      await noRegistryService.signIn({ now }).catch((caught: unknown) => caught),
    ).toMatchObject({
      code: UniAuthErrorCode.InvalidInput,
    })
    expect(
      await noRegistryService
        .signIn({
          assertion: assertion({ provider: '   ', providerUserId: 'user' }),
          now,
        })
        .catch((caught: unknown) => caught),
    ).toMatchObject({ code: UniAuthErrorCode.InvalidInput })
    expect(
      await noRegistryService
        .signIn({
          assertion: {
            providerUserId: 'user',
          } as Partial<ProviderIdentityAssertion> as ProviderIdentityAssertion,
          now,
        })
        .catch((caught: unknown) => caught),
    ).toMatchObject({ code: UniAuthErrorCode.InvalidInput })
    expect(
      await noRegistryService
        .signIn({
          assertion: {
            provider: 'email',
          } as Partial<ProviderIdentityAssertion> as ProviderIdentityAssertion,
          now,
        })
        .catch((caught: unknown) => caught),
    ).toMatchObject({ code: UniAuthErrorCode.InvalidInput })
  })

  it('covers provider sign-in, auto-link, re-auth, verification, and policy failures', async () => {
    const kit = createInMemoryAuthKit({
      policy: createDefaultAuthPolicy({
        allowAutoLink: true,
        allowMergeAccounts: true,
        requireReAuthFor: [
          AuthPolicyAction.Link,
          AuthPolicyAction.MergeAccounts,
          AuthPolicyAction.Unlink,
        ],
        reAuthMaxAgeSeconds: 60,
      }),
      clock: { now: () => now },
      sessionTtlSeconds: 5,
      verificationTtlSeconds: 5,
    })
    const provider = new StaticAuthProvider('phone', {
      providerUserId: 'phone-user',
      phone: ' +1 (555) 123-4567 ',
      phoneVerified: true,
    })

    kit.providerRegistry.register(provider)

    expect(
      await kit.service
        .signIn({ provider: 'missing', finishInput: {}, now })
        .catch((caught: unknown) => caught),
    ).toMatchObject({
      code: UniAuthErrorCode.ProviderNotFound,
    })

    const phoneUser = await kit.service.signIn({
      provider: 'phone',
      finishInput: { payload: { signed: true } },
      now,
    })
    const autoLinked = await kit.service.signIn({
      assertion: assertion({
        provider: 'oauth',
        providerUserId: 'phone-oauth',
        phone: '+15551234567',
        phoneVerified: true,
      }),
      metadata: { mode: 'phone-auto-link' },
      sessionExpiresAt: addSeconds(now, 30),
      now,
    })

    expect(autoLinked.user.id).toBe(phoneUser.user.id)

    expect(
      await kit.service
        .link({
          userId: phoneUser.user.id,
          assertion: assertion({
            provider: 'passkey',
            providerUserId: 'passkey-1',
          }),
          now,
        })
        .catch((caught: unknown) => caught),
    ).toMatchObject({ code: UniAuthErrorCode.ReAuthRequired })

    const passkey = await kit.service.link({
      userId: phoneUser.user.id,
      assertion: assertion({
        provider: 'passkey',
        providerUserId: 'passkey-1',
      }),
      reAuthenticatedAt: now,
      now,
    })

    expect(
      await kit.service
        .unlink({
          userId: phoneUser.user.id,
          identityId: passkey.identity.id,
          reAuthenticatedAt: new Date('2025-12-31T23:00:00.000Z'),
          now,
        })
        .catch((caught: unknown) => caught),
    ).toMatchObject({ code: UniAuthErrorCode.ReAuthRequired })

    const verification = await kit.service.createVerification({
      purpose: VerificationPurpose.ReAuth,
      target: ' +1 (555) 123-4567 ',
      metadata: { channel: 'sms' },
      now,
    })
    const clockVerification = await kit.service.createVerification({
      purpose: VerificationPurpose.SignIn,
      target: 'clock@example.com',
    })
    const clockSession = await kit.service.createSession({
      userId: phoneUser.user.id,
    })

    expect(verification.secret).toBeTypeOf('string')
    expect(verification.verification.target).toBe('+15551234567')
    expect(verification.verification.metadata).toEqual({ channel: 'sms' })
    expect(clockSession.expiresAt).toEqual(addSeconds(now, 5))
    expect(
      await kit.service.consumeVerification({
        verificationId: clockVerification.verification.id,
        secret: clockVerification.secret,
      }),
    ).toMatchObject({ status: VerificationStatus.Consumed })
    expect(
      await kit.service
        .consumeVerification({ verificationId: asVerificationId('missing'), secret: 'x', now })
        .catch((caught: unknown) => caught),
    ).toMatchObject({
      code: UniAuthErrorCode.VerificationNotFound,
    })
    expect(
      await kit.service
        .consumeVerification({
          verificationId: verification.verification.id,
          secret: verification.secret,
          now: addSeconds(now, 5),
        })
        .catch((caught: unknown) => caught),
    ).toMatchObject({ code: UniAuthErrorCode.VerificationExpired })

    const deniedKit = createInMemoryAuthKit({
      policy: {
        canAutoLink: () => false,
        canMergeUsers: () => false,
        canUnlinkIdentity: () => false,
        requiresReAuth: () => false,
      },
    })
    const deniedUser = await deniedKit.service.signIn({
      assertion: assertion({
        provider: 'email',
        providerUserId: 'denied',
        email: 'denied@example.com',
      }),
      now,
    })
    const deniedIdentity = await deniedKit.service.link({
      userId: deniedUser.user.id,
      assertion: assertion({ provider: 'oauth', providerUserId: 'denied-oauth' }),
      now,
    })

    expect(
      await deniedKit.service
        .unlink({ userId: deniedUser.user.id, identityId: deniedIdentity.identity.id, now })
        .catch((caught: unknown) => caught),
    ).toMatchObject({ code: UniAuthErrorCode.PolicyDenied })
  })
})
