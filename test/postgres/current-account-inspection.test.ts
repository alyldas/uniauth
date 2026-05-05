import { describe, expect, it } from 'vitest'
import { UniAuthErrorCode, addSeconds, toAuditEventView } from '../../src'
import { createPostgresTestKit, now } from './support.js'

describe('Postgres current-account inspection helpers', () => {
  it('keeps the current-account inspection aggregate in parity with the user-scoped reads', async () => {
    const { service } = await createPostgresTestKit()
    const signedIn = await service.signIn({
      assertion: {
        provider: 'email',
        providerUserId: 'pg-current-account-inspection',
        email: 'pg-current-account-inspection@example.com',
        emailVerified: true,
      },
      now,
    })

    await service.createVerification({
      purpose: 'sign-in',
      target: 'pg-current-account-inspection@example.com',
      secret: '654321',
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

  it('builds a closure export snapshot from the Postgres current-account inspection view', async () => {
    const { service } = await createPostgresTestKit()
    const signedIn = await service.signIn({
      assertion: {
        provider: 'email',
        providerUserId: 'pg-current-account-closure-export',
        email: 'pg-current-account-closure-export@example.com',
        emailVerified: true,
      },
      now,
    })

    await service.createVerification({
      purpose: 'sign-in',
      target: 'pg-current-account-closure-export@example.com',
      secret: '654321',
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
  })

  it('keeps Postgres closure export snapshots free of raw secrets and metadata', async () => {
    const { service, store } = await createPostgresTestKit()
    const signedIn = await service.signIn({
      assertion: {
        provider: 'email',
        providerUserId: 'pg-current-account-closure-export-secrets',
        email: 'pg-current-account-closure-export-secrets@example.com',
        emailVerified: true,
        metadata: {
          providerAccessToken: 'pg-raw-provider-token',
        },
      },
      now,
    })
    const credential = await service.setPassword({
      userId: signedIn.user.id,
      email: 'pg-current-account-closure-export-secrets@example.com',
      password: 'plain-password',
      now: addSeconds(now, 5),
      metadata: {
        passwordResetToken: 'pg-raw-password-metadata-token',
      },
    })
    const verification = await service.createVerification({
      purpose: 'sign-in',
      target: 'pg-current-account-closure-export-secrets@example.com',
      secret: 'pg-raw-verification-secret',
      now: addSeconds(now, 10),
      metadata: {
        deliverySecret: 'pg-raw-verification-metadata-secret',
      },
    })
    const rawCurrentSession = await store.sessionRepo.findById(signedIn.session.id)

    const snapshot = await service.getCurrentAccountClosureExportSnapshot({
      sessionToken: signedIn.sessionToken,
      now: addSeconds(now, 20),
      audit: { limit: 5 },
    })
    const serialized = JSON.stringify(snapshot)

    expect(snapshot.account.credentials).toEqual([
      expect.objectContaining({
        id: credential.id,
        subject: 'pg-current-account-closure-export-secrets@example.com',
        type: 'password',
      }),
    ])
    expect(serialized).not.toContain(credential.passwordHash)
    expect(serialized).not.toContain(rawCurrentSession!.tokenHash)
    expect(serialized).not.toContain(verification.verification.secretHash)
    expect(serialized).not.toContain('pg-raw-provider-token')
    expect(serialized).not.toContain('pg-raw-password-metadata-token')
    expect(serialized).not.toContain('pg-raw-verification-metadata-secret')
  })

  it('returns the same current-account audit page as the user-scoped audit helper on Postgres', async () => {
    const { service } = await createPostgresTestKit()
    const signedIn = await service.signIn({
      assertion: {
        provider: 'email',
        providerUserId: 'pg-current-account-audit-page',
        email: 'pg-current-account-audit-page@example.com',
        emailVerified: true,
      },
      now,
    })

    await service.createVerification({
      purpose: 'sign-in',
      target: 'pg-current-account-audit-page@example.com',
      secret: '654321',
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
  })

  it('uses the runtime clock for current-account inspection helpers on Postgres when now is omitted', async () => {
    const { service } = await createPostgresTestKit({
      clock: { now: () => now },
    })
    const signedIn = await service.signIn({
      assertion: {
        provider: 'email',
        providerUserId: 'pg-current-account-inspection-no-now',
        email: 'pg-current-account-inspection-no-now@example.com',
        emailVerified: true,
      },
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

  it('keeps stale disabled-user Postgres current-account inspection helpers neutral', async () => {
    const { service, store } = await createPostgresTestKit()
    const signedIn = await service.signIn({
      assertion: {
        provider: 'email',
        providerUserId: 'pg-disabled-current-account-inspection',
        email: 'pg-disabled-current-account-inspection@example.com',
        emailVerified: true,
      },
      now,
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
