import { describe, expect, it } from 'vitest'
import { AuthPolicyAction, UniAuthErrorCode, addSeconds, createDefaultAuthPolicy } from '../../src'
import { StaticAuthProvider, createInMemoryAuthKit } from '../../src/testing'
import { assertion, now } from './support.js'

describe('DefaultAuthService current-account link helper', () => {
  it('links raw assertions by trusted session token and keeps same-user relink idempotent', async () => {
    const { service } = createInMemoryAuthKit({
      policy: createDefaultAuthPolicy({
        requireReAuthFor: [AuthPolicyAction.Link],
      }),
    })
    const signedIn = await service.signIn({
      assertion: assertion({
        providerUserId: 'current-account-link-owner',
        email: 'current-account-link-owner@example.com',
        emailVerified: true,
      }),
      now,
    })

    await expect(
      service.linkCurrentIdentityByToken({
        sessionToken: signedIn.sessionToken,
        assertion: assertion({
          provider: 'github',
          providerUserId: 'current-account-link-github',
          email: 'current-account-link-owner@example.com',
          emailVerified: true,
        }),
        now: addSeconds(now, 10),
      }),
    ).rejects.toMatchObject({
      code: UniAuthErrorCode.ReAuthRequired,
    })

    const linked = await service.linkCurrentIdentityByToken({
      sessionToken: signedIn.sessionToken,
      assertion: assertion({
        provider: 'github',
        providerUserId: 'current-account-link-github',
        email: 'current-account-link-owner@example.com',
        emailVerified: true,
      }),
      reAuthenticatedAt: addSeconds(now, 10),
      now: addSeconds(now, 10),
    })

    expect(linked).toMatchObject({
      user: { id: signedIn.user.id },
      identity: {
        provider: 'github',
        providerUserId: 'current-account-link-github',
      },
      linked: true,
    })

    const repeated = await service.linkCurrentIdentityByToken({
      sessionToken: signedIn.sessionToken,
      assertion: assertion({
        provider: 'github',
        providerUserId: 'current-account-link-github',
        email: 'current-account-link-owner@example.com',
        emailVerified: true,
      }),
      reAuthenticatedAt: addSeconds(now, 11),
      now: addSeconds(now, 11),
    })

    expect(repeated).toMatchObject({
      user: { id: signedIn.user.id },
      identity: { id: linked.identity.id },
      linked: false,
    })
  })

  it('supports provider finish linking on the trusted current-account boundary', async () => {
    const clockNow = addSeconds(now, 6)
    const { providerRegistry, service, store } = createInMemoryAuthKit({
      clock: { now: () => clockNow },
      policy: createDefaultAuthPolicy({
        requireReAuthFor: [AuthPolicyAction.Link],
      }),
    })
    const provider = new StaticAuthProvider('telegram', {
      providerUserId: 'current-account-link-telegram',
      displayName: 'Linked Telegram',
    })

    providerRegistry.register(provider)

    const signedIn = await service.signIn({
      assertion: assertion({
        providerUserId: 'current-account-link-provider-owner',
        email: 'current-account-link-provider-owner@example.com',
        emailVerified: true,
      }),
      now,
    })

    const linked = await service.linkCurrentIdentityByToken({
      sessionToken: signedIn.sessionToken,
      provider: 'telegram',
      finishInput: { payload: { initData: 'signed' } },
      reAuthenticatedAt: addSeconds(now, 5),
      metadata: { source: 'current-account-provider-finish' },
    })

    expect(linked).toMatchObject({
      user: { id: signedIn.user.id },
      identity: {
        provider: 'telegram',
        providerUserId: 'current-account-link-telegram',
      },
      linked: true,
    })
    expect(store.listAuditEvents()).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          type: 'auth.identity_linked',
          userId: signedIn.user.id,
          metadata: {
            source: 'current-account-provider-finish',
          },
        }),
      ]),
    )
  })

  it('keeps policy-denied and already-linked paths aligned with generic link', async () => {
    const deniedKit = createInMemoryAuthKit({
      policy: {
        canAutoLink: () => true,
        canLinkIdentity: () => false,
        canMergeUsers: () => true,
        canUnlinkIdentity: () => true,
        requiresReAuth: () => false,
      },
    })
    const deniedUser = await deniedKit.service.signIn({
      assertion: assertion({
        providerUserId: 'current-account-link-denied',
        email: 'current-account-link-denied@example.com',
        emailVerified: true,
      }),
      now,
    })

    await expect(
      deniedKit.service.linkCurrentIdentityByToken({
        sessionToken: deniedUser.sessionToken,
        assertion: assertion({
          provider: 'github',
          providerUserId: 'current-account-link-denied-github',
          email: 'current-account-link-denied@example.com',
          emailVerified: true,
        }),
        now: addSeconds(now, 5),
      }),
    ).rejects.toMatchObject({
      code: UniAuthErrorCode.PolicyDenied,
    })

    const { service } = createInMemoryAuthKit()
    const alice = await service.signIn({
      assertion: assertion({
        providerUserId: 'current-account-link-alice',
        email: 'current-account-link-alice@example.com',
        emailVerified: true,
      }),
      now,
    })
    const bob = await service.signIn({
      assertion: assertion({
        providerUserId: 'current-account-link-bob',
        email: 'current-account-link-bob@example.com',
        emailVerified: true,
      }),
      now: addSeconds(now, 1),
    })

    await service.link({
      userId: bob.user.id,
      assertion: assertion({
        provider: 'github',
        providerUserId: 'current-account-link-conflict',
        email: 'current-account-link-conflict@example.com',
        emailVerified: true,
      }),
      now: addSeconds(now, 2),
    })

    await expect(
      service.linkCurrentIdentityByToken({
        sessionToken: alice.sessionToken,
        assertion: assertion({
          provider: 'github',
          providerUserId: 'current-account-link-conflict',
          email: 'current-account-link-conflict@example.com',
          emailVerified: true,
        }),
        now: addSeconds(now, 3),
      }),
    ).rejects.toMatchObject({
      code: UniAuthErrorCode.IdentityAlreadyLinked,
    })
  })

  it('keeps disabled current-account state neutral on the trusted session boundary', async () => {
    const { service, store } = createInMemoryAuthKit()
    const signedIn = await service.signIn({
      assertion: assertion({
        providerUserId: 'current-account-link-disabled',
        email: 'current-account-link-disabled@example.com',
        emailVerified: true,
      }),
      now,
    })

    await store.userRepo.update(signedIn.user.id, {
      disabledAt: addSeconds(now, 10),
    })

    await expect(
      service.linkCurrentIdentityByToken({
        sessionToken: signedIn.sessionToken,
        assertion: assertion({
          provider: 'github',
          providerUserId: 'current-account-link-disabled-github',
          email: 'current-account-link-disabled@example.com',
          emailVerified: true,
        }),
        reAuthenticatedAt: addSeconds(now, 20),
        now: addSeconds(now, 20),
      }),
    ).rejects.toMatchObject({
      code: UniAuthErrorCode.SessionNotFound,
    })
  })
})
