import { describe, expect, it } from 'vitest'
import { OtpChannel, VerificationPurpose, addSeconds } from '../../src'
import { createInMemoryAuthKit } from '../../src/testing'
import { assertion, now } from './support.js'

describe('DefaultAuthService grouped facades', () => {
  it('exposes public, account, and admin facades over the existing service methods', async () => {
    const { service } = createInMemoryAuthKit()
    const signedIn = await service.public.provider.signIn({
      assertion: assertion({
        providerUserId: 'facade-provider-user',
        email: 'facade-provider-user@example.com',
        emailVerified: true,
      }),
      now,
    })
    const updated = await service.account.profile.update({
      sessionToken: signedIn.sessionToken,
      displayName: 'Facade User',
      now,
    })
    const user = await service.admin.users.get(signedIn.user.id)
    const adminContext = await service.admin.sessions.context({
      sessionToken: signedIn.sessionToken,
      now,
    })

    expect(signedIn.session).not.toHaveProperty('tokenHash')
    expect(signedIn.identity).not.toHaveProperty('providerUserId')
    expect(updated.displayName).toBe('Facade User')
    expect(updated).not.toHaveProperty('metadata')
    expect(user.displayName).toBe('Facade User')
    expect(adminContext.session.id).toBe(signedIn.session.id)
  })

  it('returns safe account facade results for account-owned mutations', async () => {
    const { service } = createInMemoryAuthKit()
    const signedIn = await service.signIn({
      assertion: assertion({
        providerUserId: 'facade-account-owner',
        email: 'facade-account-owner@example.com',
        emailVerified: true,
      }),
      now,
    })

    const password = await service.account.password.set({
      sessionToken: signedIn.sessionToken,
      password: 'first-password',
      reAuthenticatedAt: addSeconds(now, 1),
      now: addSeconds(now, 1),
    })
    const changedPassword = await service.account.password.change({
      sessionToken: signedIn.sessionToken,
      currentPassword: 'first-password',
      newPassword: 'second-password',
      reAuthenticatedAt: addSeconds(now, 2),
      now: addSeconds(now, 2),
    })
    const contact = await service.account.contact.start({
      sessionToken: signedIn.sessionToken,
      channel: OtpChannel.Email,
      target: 'facade-new-contact@example.com',
      secret: 'contact-secret',
      reAuthenticatedAt: addSeconds(now, 3),
      now: addSeconds(now, 3),
    })
    const cancelledContact = await service.account.contact.cancel({
      sessionToken: signedIn.sessionToken,
      verificationId: contact.verificationId,
      now: addSeconds(now, 4),
    })
    const finishedContactChallenge = await service.account.contact.start({
      sessionToken: signedIn.sessionToken,
      channel: OtpChannel.Email,
      target: 'facade-finished-contact@example.com',
      secret: 'contact-secret-2',
      reAuthenticatedAt: addSeconds(now, 5),
      now: addSeconds(now, 5),
    })
    const finishedContact = await service.account.contact.finish({
      sessionToken: signedIn.sessionToken,
      verificationId: finishedContactChallenge.verificationId,
      secret: 'contact-secret-2',
      now: addSeconds(now, 6),
    })
    const reAuth = await service.account.reAuth.startOtp({
      sessionToken: signedIn.sessionToken,
      identityId: signedIn.identity.id,
      channel: OtpChannel.Email,
      secret: 'reauth-secret',
      now: addSeconds(now, 7),
    })
    const cancelledReAuth = await service.account.reAuth.cancelOtp({
      sessionToken: signedIn.sessionToken,
      verificationId: reAuth.verificationId,
      now: addSeconds(now, 8),
    })
    const linked = await service.account.identities.link({
      sessionToken: signedIn.sessionToken,
      assertion: assertion({
        provider: 'github',
        providerUserId: 'facade-linked-identity',
        email: 'facade-finished-contact@example.com',
        emailVerified: true,
      }),
      reAuthenticatedAt: addSeconds(now, 9),
      now: addSeconds(now, 9),
    })
    await service.account.profile.update({
      sessionToken: signedIn.sessionToken,
      displayName: 'Safe Account Facade',
      reAuthenticatedAt: addSeconds(now, 10),
      now: addSeconds(now, 10),
      metadata: { leaked: true },
    })
    const auditPage = await service.account.inspection.auditPage({
      sessionToken: signedIn.sessionToken,
      now: addSeconds(now, 11),
      limit: 1,
    })
    const fullAuditPage = await service.account.inspection.auditPage({
      sessionToken: signedIn.sessionToken,
      now: addSeconds(now, 11),
      limit: 100,
    })
    const closed = await service.account.closure.close({
      sessionToken: signedIn.sessionToken,
      reAuthenticatedAt: addSeconds(now, 12),
      now: addSeconds(now, 12),
      metadata: { leaked: true },
    })

    expect(password).not.toHaveProperty('passwordHash')
    expect(changedPassword).not.toHaveProperty('passwordHash')
    expect(cancelledContact).not.toHaveProperty('secretHash')
    expect(cancelledReAuth).not.toHaveProperty('secretHash')
    expect(finishedContact).toMatchObject({ email: 'facade-finished-contact@example.com' })
    expect(finishedContact).not.toHaveProperty('metadata')
    expect(linked.identity).not.toHaveProperty('providerUserId')
    expect(linked.user).not.toHaveProperty('metadata')
    expect(auditPage.events[0]).not.toHaveProperty('metadata')
    expect(auditPage.nextCursor).toBeDefined()
    expect(fullAuditPage.nextCursor).toBeUndefined()
    expect(closed.user).not.toHaveProperty('metadata')
  })

  it('returns safe public auth results from every public sign-in facade', async () => {
    const { service } = createInMemoryAuthKit()
    const owner = await service.signIn({
      assertion: assertion({
        providerUserId: 'facade-password-owner',
        email: 'facade-password-owner@example.com',
        emailVerified: true,
      }),
      now,
    })
    await service.setPassword({
      userId: owner.user.id,
      email: 'facade-password-owner@example.com',
      password: 'facade-password',
      now,
    })

    const passwordResult = await service.public.password.signIn({
      email: 'facade-password-owner@example.com',
      password: 'facade-password',
      now,
    })
    const otpChallenge = await service.public.otp.start({
      purpose: VerificationPurpose.SignIn,
      channel: OtpChannel.Email,
      target: 'facade-otp@example.com',
      secret: '123456',
      now,
    })
    const otpResult = await service.public.otp.signIn({
      verificationId: otpChallenge.verificationId,
      secret: '123456',
      channel: OtpChannel.Email,
      now,
    })
    const magicLink = await service.public.magicLink.start({
      email: 'facade-magic@example.com',
      secret: 'magic-secret',
      createLink: ({ verificationId, secret }) => `${verificationId}:${secret}`,
      now,
    })
    const magicResult = await service.public.magicLink.finish({
      verificationId: magicLink.verificationId,
      secret: 'magic-secret',
      now,
    })

    for (const result of [passwordResult, otpResult, magicResult]) {
      expect(result.session).not.toHaveProperty('tokenHash')
      expect(result.identity).not.toHaveProperty('providerUserId')
    }
  })
})
