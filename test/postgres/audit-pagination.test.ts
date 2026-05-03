import { describe, expect, it } from 'vitest'
import { AuditEventType, VerificationPurpose, addSeconds, toAuditEventCursor } from '../../src'
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
})
