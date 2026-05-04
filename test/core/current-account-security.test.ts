import { describe, expect, it } from 'vitest'
import { AuditEventType, UniAuthErrorCode, addSeconds } from '../../src'
import { createInMemoryAuthKit } from '../../src/testing'
import { assertion, now } from './support.js'

describe('DefaultAuthService current-account security helpers', () => {
  it('loads the current account-security snapshot from a trusted session token', async () => {
    const { service } = createInMemoryAuthKit()
    const signedIn = await service.signIn({ assertion: assertion(), now })
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

    expect(snapshot.currentSessionId).toBe(signedIn.session.id)
    expect(snapshot.account).toEqual({
      ...(await service.getAccountSecuritySnapshot(signedIn.user.id)),
    })
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

  it('revokes the current session by trusted session token', async () => {
    const { service } = createInMemoryAuthKit()
    const signedIn = await service.signIn({ assertion: assertion(), now })

    await service.revokeCurrentSessionByToken({
      sessionToken: signedIn.sessionToken,
      now: addSeconds(now, 20),
    })

    await expect(
      service.resolveSession({
        sessionToken: signedIn.sessionToken,
        now: addSeconds(now, 21),
      }),
    ).rejects.toMatchObject({
      code: UniAuthErrorCode.SessionNotFound,
    })
    expect(
      (await service.getAuditEvents({ userId: signedIn.user.id })).map((event) => event.type),
    ).toContain(AuditEventType.SessionRevoked)
  })

  it('revokes the current session by trusted session token without an explicit now override', async () => {
    const { service } = createInMemoryAuthKit({
      clock: { now: () => now },
    })
    const signedIn = await service.signIn({ assertion: assertion() })

    await service.revokeCurrentSessionByToken({
      sessionToken: signedIn.sessionToken,
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

  it('revokes other sessions by trusted session token while preserving the current session', async () => {
    const { service } = createInMemoryAuthKit()
    const signedIn = await service.signIn({ assertion: assertion(), now })
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

  it('keeps stale disabled-user current-account helpers neutral', async () => {
    const { service, store } = createInMemoryAuthKit()
    const signedIn = await service.signIn({ assertion: assertion(), now })

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
      service.revokeOtherSessionsByToken({
        sessionToken: signedIn.sessionToken,
        now: addSeconds(now, 20),
      }),
    ).rejects.toMatchObject({
      code: UniAuthErrorCode.SessionNotFound,
    })
  })
})
