import { describe, expect, it } from 'vitest'
import {
  AuthPolicyAction,
  PASSWORD_PROVIDER_ID,
  UniAuthErrorCode,
  addSeconds,
  createDefaultAuthPolicy,
} from '../../src'
import { createInMemoryAuthKit } from '../../src/testing'
import { assertion, now } from './support.js'

describe('DefaultAuthService current-account action helpers', () => {
  it('revokes one owned session by trusted session token while preserving the current session', async () => {
    const { service } = createInMemoryAuthKit()
    const signedIn = await service.signIn({
      assertion: assertion({
        providerUserId: 'current-account-owned-session',
        email: 'current-account-owned-session@example.com',
        emailVerified: true,
      }),
      now,
    })
    const secondSession = await service.createSession({
      userId: signedIn.user.id,
      now: addSeconds(now, 10),
    })

    const result = await service.revokeOwnedSessionByToken({
      sessionToken: signedIn.sessionToken,
      targetSessionId: secondSession.session.id,
      now: addSeconds(now, 20),
    })

    expect(result).toEqual({
      currentSessionId: signedIn.session.id,
      revokedSessionId: secondSession.session.id,
      revokedCurrentSession: false,
    })
    await expect(
      service.resolveSession({
        sessionToken: secondSession.sessionToken,
        now: addSeconds(now, 21),
      }),
    ).rejects.toMatchObject({
      code: UniAuthErrorCode.SessionNotFound,
    })
    await expect(
      service.resolveSession({
        sessionToken: signedIn.sessionToken,
        now: addSeconds(now, 21),
      }),
    ).resolves.toMatchObject({
      id: signedIn.session.id,
    })
  })

  it('can revoke the current session through the selected-session helper without an explicit now override', async () => {
    const { service } = createInMemoryAuthKit({
      clock: { now: () => now },
    })
    const signedIn = await service.signIn({
      assertion: assertion({
        providerUserId: 'current-account-revoke-current-session',
        email: 'current-account-revoke-current-session@example.com',
        emailVerified: true,
      }),
    })

    const result = await service.revokeOwnedSessionByToken({
      sessionToken: signedIn.sessionToken,
      targetSessionId: signedIn.session.id,
    })

    expect(result).toEqual({
      currentSessionId: signedIn.session.id,
      revokedSessionId: signedIn.session.id,
      revokedCurrentSession: true,
    })
    await expect(
      service.resolveSession({
        sessionToken: signedIn.sessionToken,
        now,
      }),
    ).rejects.toMatchObject({
      code: UniAuthErrorCode.SessionNotFound,
    })
  })

  it('keeps selected-session revocation neutral for foreign sessions', async () => {
    const { service } = createInMemoryAuthKit()
    const alice = await service.signIn({
      assertion: assertion({
        providerUserId: 'current-account-revoke-foreign-owner',
        email: 'current-account-revoke-foreign-owner@example.com',
        emailVerified: true,
      }),
      now,
    })
    const bob = await service.signIn({
      assertion: assertion({
        providerUserId: 'current-account-revoke-foreign-target',
        email: 'current-account-revoke-foreign-target@example.com',
        emailVerified: true,
      }),
      now: addSeconds(now, 10),
    })

    await expect(
      service.revokeOwnedSessionByToken({
        sessionToken: alice.sessionToken,
        targetSessionId: bob.session.id,
        now: addSeconds(now, 20),
      }),
    ).rejects.toMatchObject({
      code: UniAuthErrorCode.SessionNotFound,
    })
  })

  it('unlinks current-account identities by session token and preserves re-auth and last-identity rules', async () => {
    const { service } = createInMemoryAuthKit({
      policy: createDefaultAuthPolicy({
        requireReAuthFor: [AuthPolicyAction.Unlink],
      }),
    })
    const signedIn = await service.signIn({
      assertion: assertion({
        provider: 'email',
        providerUserId: 'current-account-unlink-email',
        email: 'current-account-unlink@example.com',
        emailVerified: true,
      }),
      now,
    })
    const linked = await service.link({
      userId: signedIn.user.id,
      assertion: assertion({
        provider: 'github',
        providerUserId: 'current-account-unlink-github',
        email: 'current-account-unlink@example.com',
        emailVerified: true,
      }),
      now: addSeconds(now, 5),
    })

    await expect(
      service.unlinkCurrentIdentityByToken({
        sessionToken: signedIn.sessionToken,
        identityId: linked.identity.id,
        now: addSeconds(now, 10),
      }),
    ).rejects.toMatchObject({
      code: UniAuthErrorCode.ReAuthRequired,
    })

    await service.unlinkCurrentIdentityByToken({
      sessionToken: signedIn.sessionToken,
      identityId: linked.identity.id,
      reAuthenticatedAt: addSeconds(now, 10),
      now: addSeconds(now, 10),
    })

    expect(await service.getUserIdentities(signedIn.user.id)).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          id: signedIn.identity.id,
          status: 'active',
        }),
        expect.objectContaining({
          id: linked.identity.id,
          status: 'disabled',
        }),
      ]),
    )

    await expect(
      service.unlinkCurrentIdentityByToken({
        sessionToken: signedIn.sessionToken,
        identityId: signedIn.identity.id,
        reAuthenticatedAt: addSeconds(now, 11),
        now: addSeconds(now, 11),
      }),
    ).rejects.toMatchObject({
      code: UniAuthErrorCode.LastIdentity,
    })
  })

  it('sets and changes a current-account password by trusted session token', async () => {
    const { service } = createInMemoryAuthKit({
      policy: createDefaultAuthPolicy({
        requireReAuthFor: [AuthPolicyAction.SetPassword, AuthPolicyAction.ChangePassword],
      }),
    })
    const signedIn = await service.signIn({
      assertion: assertion({
        provider: 'email',
        providerUserId: 'current-account-password',
        email: 'current-account-password@example.com',
        emailVerified: true,
      }),
      now,
    })

    await expect(
      service.setCurrentAccountPasswordByToken({
        sessionToken: signedIn.sessionToken,
        password: 'first-password',
        now: addSeconds(now, 10),
      }),
    ).rejects.toMatchObject({
      code: UniAuthErrorCode.ReAuthRequired,
    })

    const created = await service.setCurrentAccountPasswordByToken({
      sessionToken: signedIn.sessionToken,
      password: 'first-password',
      reAuthenticatedAt: addSeconds(now, 10),
      now: addSeconds(now, 10),
    })

    expect(created.type).toBe(PASSWORD_PROVIDER_ID)
    await expect(
      service.signInWithPassword({
        email: 'current-account-password@example.com',
        password: 'first-password',
        now: addSeconds(now, 11),
      }),
    ).resolves.toMatchObject({
      user: { id: signedIn.user.id },
    })

    await expect(
      service.changeCurrentAccountPasswordByToken({
        sessionToken: signedIn.sessionToken,
        currentPassword: 'first-password',
        newPassword: 'second-password',
        now: addSeconds(now, 20),
      }),
    ).rejects.toMatchObject({
      code: UniAuthErrorCode.ReAuthRequired,
    })

    await expect(
      service.changeCurrentAccountPasswordByToken({
        sessionToken: signedIn.sessionToken,
        currentPassword: 'wrong-password',
        newPassword: 'second-password',
        reAuthenticatedAt: addSeconds(now, 20),
        now: addSeconds(now, 20),
      }),
    ).rejects.toMatchObject({
      code: UniAuthErrorCode.InvalidCredentials,
    })

    const changed = await service.changeCurrentAccountPasswordByToken({
      sessionToken: signedIn.sessionToken,
      currentPassword: 'first-password',
      newPassword: 'second-password',
      reAuthenticatedAt: addSeconds(now, 21),
      now: addSeconds(now, 21),
    })

    expect(changed.subject).toBe('current-account-password@example.com')
    await expect(
      service.signInWithPassword({
        email: 'current-account-password@example.com',
        password: 'first-password',
        now: addSeconds(now, 22),
      }),
    ).rejects.toMatchObject({
      code: UniAuthErrorCode.InvalidCredentials,
    })
    await expect(
      service.signInWithPassword({
        email: 'current-account-password@example.com',
        password: 'second-password',
        now: addSeconds(now, 22),
      }),
    ).resolves.toMatchObject({
      user: { id: signedIn.user.id },
    })
  })

  it('rejects token-based password setup when the current account has no trusted email', async () => {
    const { service } = createInMemoryAuthKit()
    const signedIn = await service.signIn({
      assertion: {
        provider: 'telegram',
        providerUserId: 'current-account-password-no-email',
        displayName: 'No Email',
      },
      now,
    })

    await expect(
      service.setCurrentAccountPasswordByToken({
        sessionToken: signedIn.sessionToken,
        password: 'password',
        reAuthenticatedAt: now,
        now,
      }),
    ).rejects.toMatchObject({
      code: UniAuthErrorCode.InvalidInput,
    })
  })

  it('uses the runtime clock and forwards metadata for current-account action helpers when now is omitted', async () => {
    const { service } = createInMemoryAuthKit({
      clock: { now: () => now },
      policy: createDefaultAuthPolicy({
        requireReAuthFor: [
          AuthPolicyAction.Unlink,
          AuthPolicyAction.SetPassword,
          AuthPolicyAction.ChangePassword,
        ],
      }),
    })
    const signedIn = await service.signIn({
      assertion: assertion({
        provider: 'email',
        providerUserId: 'current-account-actions-no-now',
        email: 'current-account-actions-no-now@example.com',
        emailVerified: true,
      }),
    })
    const linked = await service.link({
      userId: signedIn.user.id,
      assertion: assertion({
        provider: 'github',
        providerUserId: 'current-account-actions-no-now-github',
        email: 'current-account-actions-no-now@example.com',
        emailVerified: true,
      }),
    })

    const created = await service.setCurrentAccountPasswordByToken({
      sessionToken: signedIn.sessionToken,
      password: 'first-password',
      reAuthenticatedAt: now,
      metadata: { source: 'current-account-set' },
    })
    const changed = await service.changeCurrentAccountPasswordByToken({
      sessionToken: signedIn.sessionToken,
      currentPassword: 'first-password',
      newPassword: 'second-password',
      reAuthenticatedAt: now,
      metadata: { source: 'current-account-change' },
    })

    await service.unlinkCurrentIdentityByToken({
      sessionToken: signedIn.sessionToken,
      identityId: linked.identity.id,
      reAuthenticatedAt: now,
      metadata: { source: 'current-account-unlink' },
    })

    expect(created.metadata).toEqual({ source: 'current-account-set' })
    expect(changed.metadata).toEqual({ source: 'current-account-change' })
    await expect(
      service.signInWithPassword({
        email: 'current-account-actions-no-now@example.com',
        password: 'second-password',
        now: addSeconds(now, 1),
      }),
    ).resolves.toMatchObject({
      user: { id: signedIn.user.id },
    })
  })

  it('keeps stale disabled-user current-account action helpers neutral', async () => {
    const { service, store } = createInMemoryAuthKit()
    const signedIn = await service.signIn({
      assertion: assertion({
        providerUserId: 'current-account-actions-disabled',
        email: 'current-account-actions-disabled@example.com',
        emailVerified: true,
      }),
      now,
    })
    const secondSession = await service.createSession({
      userId: signedIn.user.id,
      now: addSeconds(now, 5),
    })

    await store.userRepo.update(signedIn.user.id, {
      disabledAt: addSeconds(now, 10),
    })

    await expect(
      service.revokeOwnedSessionByToken({
        sessionToken: signedIn.sessionToken,
        targetSessionId: secondSession.session.id,
        now: addSeconds(now, 20),
      }),
    ).rejects.toMatchObject({
      code: UniAuthErrorCode.SessionNotFound,
    })
    await expect(
      service.unlinkCurrentIdentityByToken({
        sessionToken: signedIn.sessionToken,
        identityId: signedIn.identity.id,
        reAuthenticatedAt: addSeconds(now, 20),
        now: addSeconds(now, 20),
      }),
    ).rejects.toMatchObject({
      code: UniAuthErrorCode.SessionNotFound,
    })
    await expect(
      service.setCurrentAccountPasswordByToken({
        sessionToken: signedIn.sessionToken,
        password: 'password',
        reAuthenticatedAt: addSeconds(now, 20),
        now: addSeconds(now, 20),
      }),
    ).rejects.toMatchObject({
      code: UniAuthErrorCode.SessionNotFound,
    })
    await expect(
      service.changeCurrentAccountPasswordByToken({
        sessionToken: signedIn.sessionToken,
        currentPassword: 'password',
        newPassword: 'new-password',
        reAuthenticatedAt: addSeconds(now, 20),
        now: addSeconds(now, 20),
      }),
    ).rejects.toMatchObject({
      code: UniAuthErrorCode.SessionNotFound,
    })
  })
})
