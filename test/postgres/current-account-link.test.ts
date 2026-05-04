import { describe, expect, it } from 'vitest'
import { AuthPolicyAction, UniAuthErrorCode, addSeconds, createDefaultAuthPolicy } from '../../src'
import { now, createPostgresTestKit } from './support.js'

describe('Postgres current-account link helper', () => {
  it('links raw assertions by trusted session token and keeps same-user relink idempotent', async () => {
    const { service } = await createPostgresTestKit({
      policy: createDefaultAuthPolicy({
        requireReAuthFor: [AuthPolicyAction.Link],
      }),
    })
    const signedIn = await service.signIn({
      assertion: {
        provider: 'email',
        providerUserId: 'pg-current-account-link-owner',
        email: 'pg-current-account-link-owner@example.com',
        emailVerified: true,
      },
      now,
    })

    const linked = await service.linkCurrentIdentityByToken({
      sessionToken: signedIn.sessionToken,
      assertion: {
        provider: 'github',
        providerUserId: 'pg-current-account-link-github',
        email: 'pg-current-account-link-owner@example.com',
        emailVerified: true,
      },
      reAuthenticatedAt: addSeconds(now, 10),
      now: addSeconds(now, 10),
    })

    expect(linked).toMatchObject({
      user: { id: signedIn.user.id },
      identity: {
        provider: 'github',
        providerUserId: 'pg-current-account-link-github',
      },
      linked: true,
    })

    const repeated = await service.linkCurrentIdentityByToken({
      sessionToken: signedIn.sessionToken,
      assertion: {
        provider: 'github',
        providerUserId: 'pg-current-account-link-github',
        email: 'pg-current-account-link-owner@example.com',
        emailVerified: true,
      },
      reAuthenticatedAt: addSeconds(now, 11),
      now: addSeconds(now, 11),
    })

    expect(repeated).toMatchObject({
      user: { id: signedIn.user.id },
      identity: { id: linked.identity.id },
      linked: false,
    })
  })

  it('supports provider-finish current-account linking on Postgres', async () => {
    const { service } = await createPostgresTestKit({
      policy: createDefaultAuthPolicy({
        requireReAuthFor: [AuthPolicyAction.Link],
      }),
    })
    const signedIn = await service.signIn({
      assertion: {
        provider: 'email',
        providerUserId: 'pg-current-account-link-provider-owner',
        email: 'pg-current-account-link-provider-owner@example.com',
        emailVerified: true,
      },
      now,
    })

    const linked = await service.linkCurrentIdentityByToken({
      sessionToken: signedIn.sessionToken,
      provider: 'oidc',
      finishInput: { payload: { code: 'oidc-link' } },
      reAuthenticatedAt: addSeconds(now, 5),
      now: addSeconds(now, 5),
    })

    expect(linked).toMatchObject({
      user: { id: signedIn.user.id },
      identity: {
        provider: 'oidc',
        providerUserId: 'oidc-user',
      },
      linked: true,
    })
  })

  it('keeps policy-denied, already-linked, and stale-account paths aligned on Postgres', async () => {
    const deniedKit = await createPostgresTestKit({
      policy: {
        canAutoLink: () => true,
        canLinkIdentity: () => false,
        canMergeUsers: () => true,
        canUnlinkIdentity: () => true,
        requiresReAuth: () => false,
      },
    })
    const deniedUser = await deniedKit.service.signIn({
      assertion: {
        provider: 'email',
        providerUserId: 'pg-current-account-link-denied',
        email: 'pg-current-account-link-denied@example.com',
        emailVerified: true,
      },
      now,
    })

    await expect(
      deniedKit.service.linkCurrentIdentityByToken({
        sessionToken: deniedUser.sessionToken,
        assertion: {
          provider: 'github',
          providerUserId: 'pg-current-account-link-denied-github',
          email: 'pg-current-account-link-denied@example.com',
          emailVerified: true,
        },
        now: addSeconds(now, 5),
      }),
    ).rejects.toMatchObject({
      code: UniAuthErrorCode.PolicyDenied,
    })

    const { service, store } = await createPostgresTestKit()
    const alice = await service.signIn({
      assertion: {
        provider: 'email',
        providerUserId: 'pg-current-account-link-alice',
        email: 'pg-current-account-link-alice@example.com',
        emailVerified: true,
      },
      now,
    })

    await service.signIn({
      provider: 'oidc',
      finishInput: { payload: { code: 'oidc-conflict' } },
      now: addSeconds(now, 1),
    })

    await expect(
      service.linkCurrentIdentityByToken({
        sessionToken: alice.sessionToken,
        provider: 'oidc',
        finishInput: { payload: { code: 'oidc-conflict' } },
        now: addSeconds(now, 2),
      }),
    ).rejects.toMatchObject({
      code: UniAuthErrorCode.IdentityAlreadyLinked,
    })

    await store.userRepo.update(alice.user.id, {
      disabledAt: addSeconds(now, 10),
    })

    await expect(
      service.linkCurrentIdentityByToken({
        sessionToken: alice.sessionToken,
        assertion: {
          provider: 'github',
          providerUserId: 'pg-current-account-link-disabled-github',
          email: 'pg-current-account-link-alice@example.com',
          emailVerified: true,
        },
        reAuthenticatedAt: addSeconds(now, 20),
        now: addSeconds(now, 20),
      }),
    ).rejects.toMatchObject({
      code: UniAuthErrorCode.SessionNotFound,
    })
  })
})
