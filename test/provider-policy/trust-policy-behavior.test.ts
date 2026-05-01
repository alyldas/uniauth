import { describe, expect, it } from 'vitest'
import type { AutoLinkContext, LinkIdentityContext, MergeUsersContext } from '../../src'
import { ProviderTrustLevel, UniAuthErrorCode, createDefaultAuthPolicy } from '../../src'
import { createInMemoryAuthKit } from '../../src/testing'
import { assertion, now } from '../helpers.js'

describe('provider trust and link policy behavior', () => {
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
