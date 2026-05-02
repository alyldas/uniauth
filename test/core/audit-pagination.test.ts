import { describe, expect, it } from 'vitest'
import { AuditEventType, VerificationPurpose, addSeconds, toAuditEventCursor } from '../../src'
import { createInMemoryAuthKit } from '../../src/testing'
import { assertion, now } from './support.js'

describe('DefaultAuthService audit pagination parity', () => {
  it('keeps raw audit pagination and aggregate inspection windows aligned in-memory', async () => {
    const { service } = createInMemoryAuthKit()
    const signedIn = await service.signIn({
      assertion: assertion({
        providerUserId: 'audit-page-reader',
        email: 'audit-page-reader@example.com',
        emailVerified: true,
      }),
      now,
    })

    await service.createVerification({
      purpose: VerificationPurpose.SignIn,
      target: 'audit-page-reader@example.com',
      secret: '123456',
      now: addSeconds(now, 5),
    })
    await service.revokeSession(signedIn.session.id)

    const rawFirstPage = await service.getAuditEvents({
      userId: signedIn.user.id,
      limit: 2,
    })
    const inspectionFirstPage = await service.getAccountInspectionSnapshot({
      userId: signedIn.user.id,
      audit: { limit: 2 },
    })

    expect(rawFirstPage.map((event) => event.type)).toEqual([
      AuditEventType.SessionRevoked,
      AuditEventType.SignIn,
    ])
    expect(inspectionFirstPage.auditEvents.map((event) => event.id)).toEqual(
      rawFirstPage.map((event) => event.id),
    )

    const rawNextPage = await service.getAuditEvents({
      userId: signedIn.user.id,
      before: toAuditEventCursor(rawFirstPage.at(-1)!),
      limit: 2,
    })
    const inspectionNextPage = await service.getAccountInspectionSnapshot({
      userId: signedIn.user.id,
      audit: {
        limit: 2,
        before: toAuditEventCursor(inspectionFirstPage.auditEvents.at(-1)!),
      },
    })

    expect(rawNextPage.map((event) => event.type)).toEqual([AuditEventType.SessionCreated])
    expect(inspectionNextPage.auditEvents.map((event) => event.id)).toEqual(
      rawNextPage.map((event) => event.id),
    )

    const rawEmptyPage = await service.getAuditEvents({
      userId: signedIn.user.id,
      after: toAuditEventCursor(rawFirstPage[0]!),
      limit: 2,
    })
    const inspectionEmptyPage = await service.getAccountInspectionSnapshot({
      userId: signedIn.user.id,
      audit: {
        limit: 2,
        after: toAuditEventCursor(inspectionFirstPage.auditEvents[0]!),
      },
    })

    expect(rawEmptyPage).toEqual([])
    expect(inspectionEmptyPage.auditEvents).toEqual([])
  })
})
