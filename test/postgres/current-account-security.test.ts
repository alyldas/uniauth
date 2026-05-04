import { describe, expect, it } from 'vitest'
import { UniAuthErrorCode, addSeconds } from '../../src'
import { createPostgresTestKit, now } from './support.js'

describe('Postgres current-account security helpers', () => {
  it('matches the current-account aggregate helper with the read-side snapshot', async () => {
    const { service } = await createPostgresTestKit()
    const signedIn = await service.signIn({
      assertion: {
        provider: 'email',
        providerUserId: 'pg-current-account-security',
        email: 'pg-current-account-security@example.com',
        emailVerified: true,
      },
      now,
    })
    const secondSession = await service.createSession({
      userId: signedIn.user.id,
      now: addSeconds(now, 10),
    })
    const touchedAt = addSeconds(now, 30)

    const snapshot = await service.getCurrentAccountSecuritySnapshot({
      sessionToken: signedIn.sessionToken,
      touch: true,
      now: touchedAt,
    })
    const account = await service.getAccountSecuritySnapshot(signedIn.user.id)

    expect(snapshot.currentSessionId).toBe(signedIn.session.id)
    expect(snapshot.account).toEqual(account)
    expect(snapshot.account.sessions).toEqual([
      {
        id: signedIn.session.id,
        status: signedIn.session.status,
        createdAt: signedIn.session.createdAt,
        expiresAt: signedIn.session.expiresAt,
        lastSeenAt: touchedAt,
      },
      {
        id: secondSession.session.id,
        status: secondSession.session.status,
        createdAt: secondSession.session.createdAt,
        expiresAt: secondSession.session.expiresAt,
      },
    ])
  })

  it('revokes other Postgres sessions by trusted session token while preserving the current one', async () => {
    const { service } = await createPostgresTestKit()
    const signedIn = await service.signIn({
      assertion: {
        provider: 'email',
        providerUserId: 'pg-revoke-other-sessions',
        email: 'pg-revoke-other-sessions@example.com',
        emailVerified: true,
      },
      now,
    })
    const secondSession = await service.createSession({
      userId: signedIn.user.id,
      now: addSeconds(now, 10),
    })

    const result = await service.revokeOtherSessionsByToken({
      sessionToken: signedIn.sessionToken,
      now: addSeconds(now, 20),
    })

    expect(result).toEqual({
      userId: signedIn.user.id,
      currentSessionId: signedIn.session.id,
      revokedSessionIds: [secondSession.session.id],
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

  it('revokes other Postgres sessions by trusted session token without an explicit now override', async () => {
    const { service } = await createPostgresTestKit({
      clock: { now: () => now },
    })
    const signedIn = await service.signIn({
      assertion: {
        provider: 'email',
        providerUserId: 'pg-revoke-other-sessions-no-now',
        email: 'pg-revoke-other-sessions-no-now@example.com',
        emailVerified: true,
      },
    })
    const secondSession = await service.createSession({
      userId: signedIn.user.id,
    })

    const result = await service.revokeOtherSessionsByToken({
      sessionToken: signedIn.sessionToken,
    })

    expect(result.revokedSessionIds).toEqual([secondSession.session.id])
    expect(result.currentSessionId).toBe(signedIn.session.id)
  })

  it('keeps stale disabled-user Postgres current-account helpers neutral', async () => {
    const { service, store } = await createPostgresTestKit()
    const signedIn = await service.signIn({
      assertion: {
        provider: 'email',
        providerUserId: 'pg-disabled-current-account',
        email: 'pg-disabled-current-account@example.com',
        emailVerified: true,
      },
      now,
    })

    await store.userRepo.update(signedIn.user.id, {
      disabledAt: addSeconds(now, 10),
    })

    await expect(
      service.getCurrentAccountSecuritySnapshot({
        sessionToken: signedIn.sessionToken,
        now: addSeconds(now, 20),
      }),
    ).rejects.toMatchObject({
      code: UniAuthErrorCode.SessionNotFound,
    })
    await expect(
      service.revokeCurrentSessionByToken({
        sessionToken: signedIn.sessionToken,
        now: addSeconds(now, 20),
      }),
    ).rejects.toMatchObject({
      code: UniAuthErrorCode.SessionNotFound,
    })
  })
})
