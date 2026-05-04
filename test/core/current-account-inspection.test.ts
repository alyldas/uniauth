import { describe, expect, it } from 'vitest'
import {
  AuditEventType,
  UniAuthErrorCode,
  addSeconds,
  toAuditEventCursor,
  toAuditEventView,
} from '../../src'
import { createInMemoryAuthKit } from '../../src/testing'
import { assertion, now } from './support.js'

describe('DefaultAuthService current-account inspection helpers', () => {
  it('keeps the current-account inspection aggregate in parity with the user-scoped reads', async () => {
    const { service } = createInMemoryAuthKit()
    const signedIn = await service.signIn({
      assertion: assertion({
        providerUserId: 'current-account-inspection',
        email: 'current-account-inspection@example.com',
        emailVerified: true,
      }),
      now,
    })

    await service.createVerification({
      purpose: 'sign-in',
      target: 'current-account-inspection@example.com',
      secret: '123456',
      now: addSeconds(now, 5),
    })
    await service.createSession({
      userId: signedIn.user.id,
      now: addSeconds(now, 10),
    })

    const touchedAt = addSeconds(now, 20)
    const inspection = await service.getCurrentAccountInspectionSnapshot({
      sessionToken: signedIn.sessionToken,
      touch: true,
      now: touchedAt,
      audit: { limit: 2 },
    })
    const current = await service.getCurrentAccountSecuritySnapshot({
      sessionToken: signedIn.sessionToken,
      now: touchedAt,
    })
    const page = await service.getAuditEventPage({
      userId: signedIn.user.id,
      limit: 2,
    })

    expect(inspection.account).toEqual(current.account)
    expect(inspection.currentSessionId).toBe(current.currentSessionId)
    expect(inspection.auditEvents).toEqual(page.events.map(toAuditEventView))
    expect(inspection.nextAuditCursor).toEqual(page.nextCursor)
  })

  it('returns the same current-account audit page as the user-scoped audit helper', async () => {
    const { service } = createInMemoryAuthKit()
    const signedIn = await service.signIn({
      assertion: assertion({
        providerUserId: 'current-account-audit-page',
        email: 'current-account-audit-page@example.com',
        emailVerified: true,
      }),
      now,
    })

    await service.createVerification({
      purpose: 'sign-in',
      target: 'current-account-audit-page@example.com',
      secret: '123456',
      now: addSeconds(now, 5),
    })
    await service.createSession({
      userId: signedIn.user.id,
      now: addSeconds(now, 10),
    })
    const pageNow = addSeconds(now, 20)

    const page = await service.getCurrentAccountAuditEventPage({
      sessionToken: signedIn.sessionToken,
      now: pageNow,
      limit: 2,
    })
    const rawPage = await service.getAuditEventPage({
      userId: signedIn.user.id,
      limit: 2,
    })

    expect(page).toEqual(rawPage)
    expect(page.events.map((event) => event.type)).toEqual([
      AuditEventType.SessionCreated,
      AuditEventType.SignIn,
    ])

    const nextPage = await service.getCurrentAccountAuditEventPage({
      sessionToken: signedIn.sessionToken,
      now: pageNow,
      before: page.nextCursor,
      limit: 2,
    })
    const rawNextPage = await service.getAuditEventPage({
      userId: signedIn.user.id,
      before: rawPage.nextCursor!,
      limit: 2,
    })

    expect(nextPage).toEqual(rawNextPage)
    expect(nextPage.nextCursor).toEqual(rawNextPage.nextCursor)
  })

  it('uses the runtime clock for current-account inspection helpers when now is omitted', async () => {
    const { service } = createInMemoryAuthKit({
      clock: { now: () => now },
    })
    const signedIn = await service.signIn({
      assertion: assertion({
        providerUserId: 'current-account-inspection-no-now',
        email: 'current-account-inspection-no-now@example.com',
        emailVerified: true,
      }),
    })

    const inspection = await service.getCurrentAccountInspectionSnapshot({
      sessionToken: signedIn.sessionToken,
      audit: { limit: 1 },
    })
    const page = await service.getCurrentAccountAuditEventPage({
      sessionToken: signedIn.sessionToken,
      limit: 1,
    })

    expect(inspection.currentSessionId).toBe(signedIn.session.id)
    expect(page.events).toHaveLength(1)
  })

  it('uses the default audit window when current-account inspection input omits audit overrides', async () => {
    const { service } = createInMemoryAuthKit()
    const signedIn = await service.signIn({
      assertion: assertion({
        providerUserId: 'current-account-default-audit-window',
        email: 'current-account-default-audit-window@example.com',
        emailVerified: true,
      }),
      now,
    })

    const inspection = await service.getCurrentAccountInspectionSnapshot({
      sessionToken: signedIn.sessionToken,
      now,
    })
    const rawPage = await service.getAuditEventPage({
      userId: signedIn.user.id,
    })
    const currentPage = await service.getCurrentAccountAuditEventPage({
      sessionToken: signedIn.sessionToken,
      now,
    })

    expect(inspection.auditEvents).toEqual(rawPage.events.map(toAuditEventView))
    expect(inspection.nextAuditCursor).toEqual(rawPage.nextCursor)
    expect(currentPage).toEqual(rawPage)
  })

  it('threads explicit current-account audit filters through both aggregate and page helpers', async () => {
    const { service } = createInMemoryAuthKit()
    const signedIn = await service.signIn({
      assertion: assertion({
        providerUserId: 'current-account-filtered-audit',
        email: 'current-account-filtered-audit@example.com',
        emailVerified: true,
      }),
      now,
    })

    const secondSession = await service.createSession({
      userId: signedIn.user.id,
      now: addSeconds(now, 10),
    })
    const rawAll = await service.getAuditEventPage({
      userId: signedIn.user.id,
      limit: 10,
    })
    const after = toAuditEventCursor(rawAll.events[0]!)
    const before = toAuditEventCursor(rawAll.events.at(-1)!)
    const pageNow = addSeconds(now, 20)

    const currentPage = await service.getCurrentAccountAuditEventPage({
      sessionToken: signedIn.sessionToken,
      now: pageNow,
      type: AuditEventType.SessionCreated,
      identityId: signedIn.identity.id,
      sessionId: secondSession.session.id,
      after,
      before,
      limit: 2,
    })
    const rawPage = await service.getAuditEventPage({
      userId: signedIn.user.id,
      type: AuditEventType.SessionCreated,
      identityId: signedIn.identity.id,
      sessionId: secondSession.session.id,
      after,
      before,
      limit: 2,
    })
    const inspection = await service.getCurrentAccountInspectionSnapshot({
      sessionToken: signedIn.sessionToken,
      now: pageNow,
      audit: {
        type: AuditEventType.SessionCreated,
        identityId: signedIn.identity.id,
        sessionId: secondSession.session.id,
        after,
        before,
        limit: 2,
      },
    })

    expect(currentPage).toEqual(rawPage)
    expect(inspection.auditEvents).toEqual(rawPage.events.map(toAuditEventView))
    expect(inspection.nextAuditCursor).toEqual(rawPage.nextCursor)
  })

  it('keeps stale disabled-user current-account inspection helpers neutral', async () => {
    const { service, store } = createInMemoryAuthKit()
    const signedIn = await service.signIn({ assertion: assertion(), now })

    await store.userRepo.update(signedIn.user.id, {
      disabledAt: addSeconds(now, 10),
    })

    await expect(
      service.getCurrentAccountInspectionSnapshot({
        sessionToken: signedIn.sessionToken,
        now: addSeconds(now, 20),
        audit: { limit: 1 },
      }),
    ).rejects.toMatchObject({
      code: UniAuthErrorCode.SessionNotFound,
    })
    await expect(
      service.getCurrentAccountAuditEventPage({
        sessionToken: signedIn.sessionToken,
        now: addSeconds(now, 20),
        limit: 1,
      }),
    ).rejects.toMatchObject({
      code: UniAuthErrorCode.SessionNotFound,
    })
  })
})
