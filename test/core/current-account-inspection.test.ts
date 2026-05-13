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

  it('builds a closure export snapshot from the current-account inspection view', async () => {
    const { service } = createInMemoryAuthKit()
    const signedIn = await service.signIn({
      assertion: assertion({
        providerUserId: 'current-account-closure-export',
        email: 'current-account-closure-export@example.com',
        emailVerified: true,
      }),
      now,
    })

    await service.createVerification({
      purpose: 'sign-in',
      target: 'current-account-closure-export@example.com',
      secret: '123456',
      now: addSeconds(now, 5),
    })
    await service.createSession({
      userId: signedIn.user.id,
      now: addSeconds(now, 10),
    })

    const generatedAt = addSeconds(now, 20)
    const exportSnapshot = await service.getCurrentAccountClosureExportSnapshot({
      sessionToken: signedIn.sessionToken,
      touch: true,
      now: generatedAt,
      audit: { limit: 2 },
    })
    const inspection = await service.getCurrentAccountInspectionSnapshot({
      sessionToken: signedIn.sessionToken,
      touch: true,
      now: generatedAt,
      audit: { limit: 2 },
    })

    expect(exportSnapshot).toEqual({
      ...inspection,
      generatedAt,
    })
    expect(exportSnapshot.currentSessionId).toBe(signedIn.session.id)
    expect(exportSnapshot.auditEvents).toHaveLength(2)
    expect(exportSnapshot.nextAuditCursor).toEqual(inspection.nextAuditCursor)
  })

  it('keeps closure export snapshots free of raw credential, session, and verification secrets', async () => {
    const { service, store } = createInMemoryAuthKit()
    const signedIn = await service.signIn({
      assertion: assertion({
        providerUserId: 'current-account-closure-export-secrets',
        email: 'current-account-closure-export-secrets@example.com',
        emailVerified: true,
        metadata: {
          providerAccessToken: 'raw-provider-token',
        },
      }),
      now,
    })
    const credential = await service.setPassword({
      userId: signedIn.user.id,
      email: 'current-account-closure-export-secrets@example.com',
      password: 'plain-password',
      now: addSeconds(now, 5),
      metadata: {
        passwordResetToken: 'raw-password-metadata-token',
      },
    })
    const verification = await service.createVerification({
      purpose: 'sign-in',
      target: 'current-account-closure-export-secrets@example.com',
      secret: 'raw-verification-secret',
      now: addSeconds(now, 10),
      metadata: {
        deliverySecret: 'raw-verification-metadata-secret',
      },
    })
    const otherSession = await service.createSession({
      userId: signedIn.user.id,
      now: addSeconds(now, 15),
      metadata: {
        deviceToken: 'raw-session-metadata-token',
      },
    })
    const rawCurrentSession = await store.sessionRepo.findById(signedIn.session.id)

    const snapshot = await service.getCurrentAccountClosureExportSnapshot({
      sessionToken: signedIn.sessionToken,
      now: addSeconds(now, 20),
      audit: { limit: 5 },
    })
    const serialized = JSON.stringify(snapshot)

    expect(snapshot.account.user.id).toBe(signedIn.user.id)
    expect(snapshot.account.credentials).toEqual([
      expect.objectContaining({
        id: credential.id,
        subject: 'current-account-closure-export-secrets@example.com',
        type: 'password',
      }),
    ])
    expect(snapshot.account.sessions.map((session) => session.id)).toEqual(
      expect.arrayContaining([signedIn.session.id, otherSession.session.id]),
    )
    expect(serialized).not.toContain(credential.passwordHash)
    expect(serialized).not.toContain(rawCurrentSession!.tokenHash)
    expect(serialized).not.toContain(otherSession.sessionToken)
    expect(serialized).not.toContain(verification.verification.secretHash)
    expect(serialized).not.toContain('raw-provider-token')
    expect(serialized).not.toContain('raw-password-metadata-token')
    expect(serialized).not.toContain('raw-verification-metadata-secret')
    expect(serialized).not.toContain('raw-session-metadata-token')
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
    const exportSnapshot = await service.getCurrentAccountClosureExportSnapshot({
      sessionToken: signedIn.sessionToken,
      audit: { limit: 1 },
    })
    const page = await service.getCurrentAccountAuditEventPage({
      sessionToken: signedIn.sessionToken,
      limit: 1,
    })

    expect(inspection.currentSessionId).toBe(signedIn.session.id)
    expect(exportSnapshot.currentSessionId).toBe(signedIn.session.id)
    expect(exportSnapshot.generatedAt).toEqual(now)
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

    await expect(
      // @ts-expect-error runtime validation for untyped callers
      service.getCurrentAccountInspectionSnapshot(null),
    ).rejects.toMatchObject({
      code: UniAuthErrorCode.InvalidInput,
    })
    await expect(
      // @ts-expect-error runtime validation for untyped callers
      service.getCurrentAccountAuditEventPage(123),
    ).rejects.toMatchObject({
      code: UniAuthErrorCode.InvalidInput,
    })
    await expect(
      // @ts-expect-error runtime validation for untyped callers
      service.getCurrentAccountClosureExportSnapshot([]),
    ).rejects.toMatchObject({
      code: UniAuthErrorCode.InvalidInput,
    })

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
    await expect(
      service.getCurrentAccountClosureExportSnapshot({
        sessionToken: signedIn.sessionToken,
        now: addSeconds(now, 20),
        audit: { limit: 1 },
      }),
    ).rejects.toMatchObject({
      code: UniAuthErrorCode.SessionNotFound,
    })
  })
})
