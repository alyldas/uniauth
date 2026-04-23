import { describe, expect, it } from 'vitest'
import {
  type AutoLinkContext,
  AuthPolicyAction,
  type LinkIdentityContext,
  type MergeUsersContext,
  ProviderTrustLevel,
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
    expect(
      await noRegistryService
        .signIn({
          assertion: assertion({
            provider: 'oauth',
            providerUserId: 'invalid-trust',
            trust: {
              level: 'unsupported' as 'trusted',
            },
          }),
          now,
        })
        .catch((caught: unknown) => caught),
    ).toMatchObject({ code: UniAuthErrorCode.InvalidInput })
    expect(
      await noRegistryService
        .signIn({
          assertion: {
            provider: 'oauth',
            providerUserId: 'invalid-trust-level-type',
            trust: {
              level: 1,
            },
          } as unknown as ProviderIdentityAssertion,
          now,
        })
        .catch((caught: unknown) => caught),
    ).toMatchObject({ code: UniAuthErrorCode.InvalidInput })
    expect(
      await noRegistryService
        .signIn({
          assertion: {
            provider: 'oauth',
            providerUserId: 'invalid-trust-signals-type',
            trust: {
              level: 'trusted',
              signals: 'not-an-array',
            },
          } as unknown as ProviderIdentityAssertion,
          now,
        })
        .catch((caught: unknown) => caught),
    ).toMatchObject({ code: UniAuthErrorCode.InvalidInput })
    expect(
      await noRegistryService
        .signIn({
          assertion: {
            provider: 'oauth',
            providerUserId: 'invalid-trust-type',
            trust: {
              level: 'trusted',
              signals: [123],
            },
          } as unknown as ProviderIdentityAssertion,
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
        canLinkIdentity: () => true,
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

  it('exposes provider trust context to auto-link, link, and merge policy decisions', async () => {
    const policy = {
      ...createDefaultAuthPolicy({
        allowAutoLink: true,
        allowMergeAccounts: true,
        requireReAuthFor: [],
      }),
      canAutoLink(context: AutoLinkContext) {
        return (
          context.assertion.trust?.level === ProviderTrustLevel.Trusted &&
          context.existingIdentities.every(
            (identity) => identity.trust?.level === ProviderTrustLevel.Trusted,
          )
        )
      },
      canLinkIdentity(context: LinkIdentityContext) {
        return context.assertion.trust?.level !== ProviderTrustLevel.Untrusted
      },
      canMergeUsers(context: MergeUsersContext) {
        const identities = [...context.sourceIdentities, ...context.targetIdentities]
        return identities.every(
          (identity) => identity.trust?.level !== ProviderTrustLevel.Untrusted,
        )
      },
    }
    const { service } = createInMemoryAuthKit({ policy })

    const untrustedUser = await service.signIn({
      assertion: assertion({
        provider: 'legacy-oauth',
        providerUserId: 'legacy-user',
        email: 'shared@example.com',
        emailVerified: true,
        trust: {
          level: ProviderTrustLevel.Untrusted,
          signals: ['legacy-email-claim'],
        },
      }),
      now,
    })

    const trustedCandidate = await service.signIn({
      assertion: assertion({
        provider: 'trusted-oauth',
        providerUserId: 'trusted-user',
        email: 'shared@example.com',
        emailVerified: true,
        trust: {
          level: ProviderTrustLevel.Trusted,
          signals: ['oidc-email-verified'],
        },
      }),
      now,
    })

    expect(trustedCandidate.user.id).not.toBe(untrustedUser.user.id)
    expect(untrustedUser.identity.trust?.signals).toEqual(['legacy-email-claim'])

    const trustedPrimary = await service.signIn({
      assertion: assertion({
        provider: 'trusted-primary',
        providerUserId: 'trusted-primary-user',
        email: 'pair@example.com',
        emailVerified: true,
        trust: {
          level: ProviderTrustLevel.Trusted,
        },
      }),
      now,
    })
    const trustedAutoLinked = await service.signIn({
      assertion: assertion({
        provider: 'trusted-secondary',
        providerUserId: 'trusted-secondary-user',
        email: 'pair@example.com',
        emailVerified: true,
        trust: {
          level: ProviderTrustLevel.Trusted,
        },
      }),
      now,
    })

    expect(trustedAutoLinked.user.id).toBe(trustedPrimary.user.id)
    expect(trustedAutoLinked.isNewIdentity).toBe(true)

    expect(
      await service
        .link({
          userId: trustedPrimary.user.id,
          assertion: assertion({
            provider: 'link-oauth',
            providerUserId: 'link-oauth-user',
            trust: {
              level: ProviderTrustLevel.Untrusted,
            },
          }),
          now,
        })
        .catch((caught: unknown) => caught),
    ).toMatchObject({ code: UniAuthErrorCode.PolicyDenied })

    const mergeTarget = await service.signIn({
      assertion: assertion({
        provider: 'merge-target',
        providerUserId: 'merge-target-user',
        email: 'merge-target@example.com',
        emailVerified: true,
        trust: {
          level: ProviderTrustLevel.Trusted,
        },
      }),
      now,
    })

    expect(
      await service
        .mergeAccounts({
          sourceUserId: untrustedUser.user.id,
          targetUserId: mergeTarget.user.id,
          reAuthenticatedAt: now,
          now,
        })
        .catch((caught: unknown) => caught),
    ).toMatchObject({ code: UniAuthErrorCode.PolicyDenied })
  })

  it('keeps exact link behavior ahead of trust policy denial', async () => {
    const sameUserKit = createInMemoryAuthKit({
      policy: {
        ...createDefaultAuthPolicy(),
        canLinkIdentity: () => false,
      },
    })
    const baseUser = await sameUserKit.service.signIn({
      assertion: assertion({
        provider: 'email',
        providerUserId: 'base-user',
        email: 'base@example.com',
        emailVerified: true,
      }),
      now,
    })

    const repeated = await sameUserKit.service.link({
      userId: baseUser.user.id,
      assertion: assertion({
        provider: baseUser.identity.provider,
        providerUserId: baseUser.identity.providerUserId,
      }),
      now,
    })

    expect(repeated.linked).toBe(false)

    const otherUser = await sameUserKit.service.signIn({
      assertion: assertion({
        provider: 'email',
        providerUserId: 'other-user',
        email: 'other@example.com',
        emailVerified: true,
      }),
      now,
    })

    expect(
      await sameUserKit.service
        .link({
          userId: otherUser.user.id,
          assertion: assertion({
            provider: baseUser.identity.provider,
            providerUserId: baseUser.identity.providerUserId,
          }),
          now,
        })
        .catch((caught: unknown) => caught),
    ).toMatchObject({ code: UniAuthErrorCode.IdentityAlreadyLinked })
  })

  it('defaults link policy to allow when a legacy custom policy omits the hook', async () => {
    const compatibilityKit = createInMemoryAuthKit({
      policy: {
        canAutoLink: () => false,
        canMergeUsers: () => false,
        canUnlinkIdentity: () => true,
        requiresReAuth: () => false,
      },
    })
    const baseUser = await compatibilityKit.service.signIn({
      assertion: assertion({
        provider: 'email',
        providerUserId: 'compat-user',
        email: 'compat@example.com',
        emailVerified: true,
      }),
      now,
    })

    const linked = await compatibilityKit.service.link({
      userId: baseUser.user.id,
      assertion: assertion({
        provider: 'compat-oauth',
        providerUserId: 'compat-oauth-user',
      }),
      now,
    })

    expect(linked.linked).toBe(true)
  })
})
