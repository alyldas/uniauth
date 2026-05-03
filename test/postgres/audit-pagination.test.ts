import { describe, expect, it } from 'vitest'
import {
  AuditEventType,
  VerificationPurpose,
  addSeconds,
  toAuditEventCursor,
  toAuditEventView,
} from '../../src'
import { createPostgresTestKit, now } from './support.js'

describe('Postgres audit pagination parity', () => {
  it('returns older-page metadata for the raw audit page helper on Postgres', async () => {
    const { service } = await createPostgresTestKit()
    const signedIn = await service.signIn({
      assertion: {
        provider: 'email',
        providerUserId: 'pg-audit-page-reader',
        email: 'pg-audit-page-reader@example.com',
        emailVerified: true,
      },
      now,
    })

    await service.createVerification({
      purpose: VerificationPurpose.SignIn,
      target: 'pg-audit-page-reader@example.com',
      secret: '654321',
      now: addSeconds(now, 5),
    })
    await service.revokeSession(signedIn.session.id)

    const rawFirstPage = await service.getAuditEventPage({
      userId: signedIn.user.id,
      limit: 2,
    })

    expect(rawFirstPage.events.map((event) => event.type)).toEqual([
      AuditEventType.SessionRevoked,
      AuditEventType.SignIn,
    ])
    expect(rawFirstPage.nextCursor).toEqual(toAuditEventCursor(rawFirstPage.events[1]!))

    const rawNextPage = await service.getAuditEventPage({
      userId: signedIn.user.id,
      before: rawFirstPage.nextCursor!,
      limit: 2,
    })

    expect(rawNextPage.events.map((event) => event.type)).toEqual([AuditEventType.SessionCreated])
    expect(rawNextPage.nextCursor).toBeUndefined()

    const rawEmptyPage = await service.getAuditEventPage({
      userId: signedIn.user.id,
      after: toAuditEventCursor(rawFirstPage.events[0]!),
      limit: 2,
    })

    expect(rawEmptyPage.events).toEqual([])
    expect(rawEmptyPage.nextCursor).toBeUndefined()
  })

  it('keeps aggregate inspection audit windows in parity with the raw page helper on Postgres', async () => {
    const { service } = await createPostgresTestKit()
    const signedIn = await service.signIn({
      assertion: {
        provider: 'email',
        providerUserId: 'pg-inspection-audit-page-reader',
        email: 'pg-inspection-audit-page-reader@example.com',
        emailVerified: true,
      },
      now,
    })

    await service.createVerification({
      purpose: VerificationPurpose.SignIn,
      target: 'pg-inspection-audit-page-reader@example.com',
      secret: '654321',
      now: addSeconds(now, 5),
    })
    await service.revokeSession(signedIn.session.id)

    const rawFirstPage = await service.getAuditEventPage({
      userId: signedIn.user.id,
      limit: 2,
    })
    const inspectionFirstPage = await service.getAccountInspectionSnapshot({
      userId: signedIn.user.id,
      audit: { limit: 2 },
    })

    expect(inspectionFirstPage.auditEvents).toEqual(rawFirstPage.events.map(toAuditEventView))
    expect(inspectionFirstPage.nextAuditCursor).toEqual(rawFirstPage.nextCursor)

    const rawNextPage = await service.getAuditEventPage({
      userId: signedIn.user.id,
      before: rawFirstPage.nextCursor!,
      limit: 2,
    })
    const inspectionNextPage = await service.getAccountInspectionSnapshot({
      userId: signedIn.user.id,
      audit: {
        limit: 2,
        before: inspectionFirstPage.nextAuditCursor,
      },
    })

    expect(inspectionNextPage.auditEvents).toEqual(rawNextPage.events.map(toAuditEventView))
    expect(inspectionNextPage.nextAuditCursor).toEqual(rawNextPage.nextCursor)

    const rawEmptyPage = await service.getAuditEventPage({
      userId: signedIn.user.id,
      after: toAuditEventCursor(rawFirstPage.events[0]!),
      limit: 2,
    })
    const inspectionEmptyPage = await service.getAccountInspectionSnapshot({
      userId: signedIn.user.id,
      audit: {
        limit: 2,
        after: toAuditEventCursor(inspectionFirstPage.auditEvents[0]!),
      },
    })

    expect(inspectionEmptyPage.auditEvents).toEqual(rawEmptyPage.events.map(toAuditEventView))
    expect(inspectionEmptyPage.nextAuditCursor).toEqual(rawEmptyPage.nextCursor)
  })
})
