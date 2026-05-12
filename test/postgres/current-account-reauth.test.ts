import { describe, expect, it } from 'vitest'
import {
  AuditEventType,
  AuthPolicyAction,
  OtpChannel,
  UniAuthErrorCode,
  VerificationPurpose,
  addSeconds,
  createDefaultAuthPolicy,
} from '../../src'
import { createPostgresTestKit, now } from './support.js'

describe('Postgres current-account re-auth helpers', () => {
  it('keeps current-account OTP re-auth aligned with generic re-auth verification semantics on Postgres', async () => {
    const { service, emailSender, store } = await createPostgresTestKit({
      policy: createDefaultAuthPolicy({
        requireReAuthFor: [AuthPolicyAction.Unlink],
      }),
    })
    const signedIn = await service.signIn({
      assertion: {
        provider: 'email',
        providerUserId: 'pg-current-account-reauth-email',
        email: 'pg-current-account-reauth@example.com',
        emailVerified: true,
      },
      now,
    })
    const linked = await service.link({
      userId: signedIn.user.id,
      assertion: {
        provider: 'github',
        providerUserId: 'pg-current-account-reauth-github',
        email: 'pg-current-account-reauth@example.com',
        emailVerified: true,
      },
      now: addSeconds(now, 5),
    })

    const challenge = await service.startCurrentAccountOtpReAuth({
      sessionToken: signedIn.sessionToken,
      identityId: signedIn.identity.id,
      channel: OtpChannel.Email,
      secret: '654321',
      now: addSeconds(now, 10),
    })

    expect(emailSender.listMessages()[0]).toMatchObject({
      to: 'pg-current-account-reauth@example.com',
      text: 'Your sign-in code is 654321.',
    })

    const confirmation = await service.finishCurrentAccountOtpReAuth({
      sessionToken: signedIn.sessionToken,
      verificationId: challenge.verificationId,
      secret: '654321',
      now: addSeconds(now, 11),
    })

    await service.unlinkCurrentIdentityByToken({
      sessionToken: signedIn.sessionToken,
      identityId: linked.identity.id,
      reAuthenticatedAt: confirmation.reAuthenticatedAt,
      now: addSeconds(now, 11),
    })

    expect((await store.auditLogRepo.list()).map((event) => event.type)).toEqual(
      expect.arrayContaining([
        AuditEventType.VerificationCreated,
        AuditEventType.VerificationConsumed,
        AuditEventType.IdentityUnlinked,
      ]),
    )
  })

  it('keeps current-account OTP re-auth resend and cancellation aligned with trusted verification ownership on Postgres', async () => {
    const { service, emailSender, store } = await createPostgresTestKit()
    const signedIn = await service.signIn({
      assertion: {
        provider: 'email',
        providerUserId: 'pg-current-account-reauth-resend-owner',
        email: 'pg-current-account-reauth-resend@example.com',
        emailVerified: true,
      },
      now,
    })

    const challenge = await service.startCurrentAccountOtpReAuth({
      sessionToken: signedIn.sessionToken,
      identityId: signedIn.identity.id,
      channel: OtpChannel.Email,
      secret: '111111',
      now: addSeconds(now, 10),
      metadata: { source: 'pg-current-account-reauth-start' },
    })

    const resent = await service.resendCurrentAccountOtpReAuth({
      sessionToken: signedIn.sessionToken,
      verificationId: challenge.verificationId,
      secret: '222222',
      ttlSeconds: 120,
      now: addSeconds(now, 20),
      metadata: { source: 'pg-current-account-reauth-resend' },
    })

    expect(resent.verificationId).not.toBe(challenge.verificationId)
    expect(emailSender.listMessages()[1]).toMatchObject({
      to: 'pg-current-account-reauth-resend@example.com',
      text: 'Your sign-in code is 222222.',
      metadata: {
        verificationId: resent.verificationId,
        purpose: VerificationPurpose.ReAuth,
        delivery: OtpChannel.Email,
      },
    })

    expect(await service.getVerification(challenge.verificationId)).toMatchObject({
      id: challenge.verificationId,
      expiresAt: addSeconds(now, 20),
    })
    expect(await service.getVerification(resent.verificationId)).toMatchObject({
      id: resent.verificationId,
      purpose: VerificationPurpose.ReAuth,
      target: 'pg-current-account-reauth-resend@example.com',
      metadata: expect.objectContaining({
        requestMetadata: { source: 'pg-current-account-reauth-resend' },
      }),
    })

    const cancelled = await service.cancelCurrentAccountOtpReAuth({
      sessionToken: signedIn.sessionToken,
      verificationId: resent.verificationId,
      now: addSeconds(now, 21),
      metadata: { source: 'pg-current-account-reauth-cancel' },
    })

    expect(cancelled).toMatchObject({
      id: resent.verificationId,
      expiresAt: addSeconds(now, 21),
    })
    expect(await store.auditLogRepo.list()).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          type: AuditEventType.VerificationCancelled,
          metadata: {
            verificationId: resent.verificationId,
            purpose: VerificationPurpose.ReAuth,
            currentAccountOtpReAuth: {
              userId: signedIn.user.id,
              sessionId: signedIn.session.id,
              channel: OtpChannel.Email,
            },
            requestMetadata: { source: 'pg-current-account-reauth-cancel' },
          },
        }),
      ]),
    )

    await expect(
      service.finishCurrentAccountOtpReAuth({
        sessionToken: signedIn.sessionToken,
        verificationId: resent.verificationId,
        secret: '222222',
        now: addSeconds(now, 22),
      }),
    ).rejects.toMatchObject({
      code: UniAuthErrorCode.VerificationExpired,
    })
  })

  it('keeps current-account OTP re-auth resend and cancellation neutral on Postgres', async () => {
    const { service } = await createPostgresTestKit()
    const alice = await service.signIn({
      assertion: {
        provider: 'email',
        providerUserId: 'pg-current-account-reauth-neutral-owner',
        email: 'pg-current-account-reauth-neutral-owner@example.com',
        emailVerified: true,
      },
      now,
    })
    const bob = await service.signIn({
      assertion: {
        provider: 'email',
        providerUserId: 'pg-current-account-reauth-neutral-foreign',
        email: 'pg-current-account-reauth-neutral-foreign@example.com',
        emailVerified: true,
      },
      now: addSeconds(now, 1),
    })

    const ownedChallenge = await service.startCurrentAccountOtpReAuth({
      sessionToken: alice.sessionToken,
      identityId: alice.identity.id,
      channel: OtpChannel.Email,
      secret: '333333',
      now: addSeconds(now, 10),
    })
    const signInChallenge = await service.startOtpChallenge({
      purpose: VerificationPurpose.SignIn,
      channel: OtpChannel.Email,
      target: 'pg-current-account-reauth-neutral-owner@example.com',
      secret: '444444',
      now: addSeconds(now, 11),
    })

    await expect(
      service.resendCurrentAccountOtpReAuth({
        sessionToken: bob.sessionToken,
        verificationId: ownedChallenge.verificationId,
        now: addSeconds(now, 20),
      }),
    ).rejects.toMatchObject({
      code: UniAuthErrorCode.VerificationNotFound,
    })

    await expect(
      service.cancelCurrentAccountOtpReAuth({
        sessionToken: alice.sessionToken,
        verificationId: signInChallenge.verificationId,
        now: addSeconds(now, 21),
      }),
    ).rejects.toMatchObject({
      code: UniAuthErrorCode.VerificationNotFound,
    })
  })

  it('keeps current-account password confirmation aligned with change-password flows on Postgres', async () => {
    const { service, store } = await createPostgresTestKit({
      policy: createDefaultAuthPolicy({
        requireReAuthFor: [AuthPolicyAction.SetPassword, AuthPolicyAction.ChangePassword],
      }),
    })
    const signedIn = await service.signIn({
      assertion: {
        provider: 'email',
        providerUserId: 'pg-current-account-password-reauth',
        email: 'pg-current-account-password-reauth@example.com',
        emailVerified: true,
      },
      now,
    })

    await service.setCurrentAccountPasswordByToken({
      sessionToken: signedIn.sessionToken,
      password: 'first-password',
      reAuthenticatedAt: addSeconds(now, 5),
      now: addSeconds(now, 5),
    })

    const auditCountBeforeConfirmation = (await store.auditLogRepo.list()).length
    const confirmation = await service.confirmCurrentAccountPasswordByToken({
      sessionToken: signedIn.sessionToken,
      currentPassword: 'first-password',
      now: addSeconds(now, 20),
    })

    expect(confirmation).toEqual({
      currentSessionId: signedIn.session.id,
      userId: signedIn.user.id,
      reAuthenticatedAt: addSeconds(now, 20),
    })
    expect(await store.auditLogRepo.list()).toHaveLength(auditCountBeforeConfirmation)

    await service.changeCurrentAccountPasswordByToken({
      sessionToken: signedIn.sessionToken,
      currentPassword: 'first-password',
      newPassword: 'second-password',
      reAuthenticatedAt: confirmation.reAuthenticatedAt,
      now: addSeconds(now, 20),
    })

    await expect(
      service.confirmCurrentAccountPasswordByToken({
        sessionToken: signedIn.sessionToken,
        currentPassword: 'wrong-password',
        now: addSeconds(now, 21),
      }),
    ).rejects.toMatchObject({
      code: UniAuthErrorCode.InvalidCredentials,
    })
  })

  it('keeps current-account recent-auth status and assert helpers aligned with token-based password actions on Postgres', async () => {
    const { service, store } = await createPostgresTestKit({
      policy: createDefaultAuthPolicy({
        requireReAuthFor: [AuthPolicyAction.SetPassword, AuthPolicyAction.ChangePassword],
      }),
    })
    const signedIn = await service.signIn({
      assertion: {
        provider: 'email',
        providerUserId: 'pg-current-account-recent-auth-status',
        email: 'pg-current-account-recent-auth-status@example.com',
        emailVerified: true,
      },
      now,
    })

    await service.setCurrentAccountPasswordByToken({
      sessionToken: signedIn.sessionToken,
      password: 'first-password',
      reAuthenticatedAt: addSeconds(now, 1),
      now: addSeconds(now, 1),
    })

    const auditCountBeforeStatus = (await store.auditLogRepo.list()).length
    const requiredStatus = await service.getCurrentAccountReAuthStatus({
      sessionToken: signedIn.sessionToken,
      action: AuthPolicyAction.ChangePassword,
      now: addSeconds(now, 10),
    })

    expect(requiredStatus).toEqual({
      currentSessionId: signedIn.session.id,
      userId: signedIn.user.id,
      action: AuthPolicyAction.ChangePassword,
      required: true,
      checkedAt: addSeconds(now, 10),
    })
    expect(await store.auditLogRepo.list()).toHaveLength(auditCountBeforeStatus)

    await expect(
      service.assertCurrentAccountReAuth({
        sessionToken: signedIn.sessionToken,
        action: AuthPolicyAction.ChangePassword,
        now: addSeconds(now, 10),
      }),
    ).rejects.toMatchObject({
      code: UniAuthErrorCode.ReAuthRequired,
    })

    expect(await store.auditLogRepo.list()).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          type: AuditEventType.PolicyDenied,
          userId: signedIn.user.id,
          metadata: {
            reason: 're-auth-required',
            action: AuthPolicyAction.ChangePassword,
          },
        }),
      ]),
    )

    const confirmation = await service.confirmCurrentAccountPasswordByToken({
      sessionToken: signedIn.sessionToken,
      currentPassword: 'first-password',
      now: addSeconds(now, 20),
    })

    expect(
      await service.getCurrentAccountReAuthStatus({
        sessionToken: signedIn.sessionToken,
        action: AuthPolicyAction.ChangePassword,
        reAuthenticatedAt: confirmation.reAuthenticatedAt,
        now: addSeconds(now, 20),
      }),
    ).toEqual({
      currentSessionId: signedIn.session.id,
      userId: signedIn.user.id,
      action: AuthPolicyAction.ChangePassword,
      required: false,
      checkedAt: addSeconds(now, 20),
      reAuthenticatedAt: addSeconds(now, 20),
    })

    expect(
      await service.assertCurrentAccountReAuth({
        sessionToken: signedIn.sessionToken,
        action: AuthPolicyAction.ChangePassword,
        reAuthenticatedAt: confirmation.reAuthenticatedAt,
        now: addSeconds(now, 20),
      }),
    ).toEqual({
      currentSessionId: signedIn.session.id,
      userId: signedIn.user.id,
      action: AuthPolicyAction.ChangePassword,
      checkedAt: addSeconds(now, 20),
      reAuthenticatedAt: addSeconds(now, 20),
    })
  })

  it('keeps stale disabled-user Postgres current-account re-auth helpers neutral', async () => {
    const { service, store } = await createPostgresTestKit()
    const signedIn = await service.signIn({
      assertion: {
        provider: 'email',
        providerUserId: 'pg-current-account-reauth-disabled',
        email: 'pg-current-account-reauth-disabled@example.com',
        emailVerified: true,
      },
      now,
    })

    await store.userRepo.update(signedIn.user.id, {
      disabledAt: addSeconds(now, 10),
    })

    await expect(
      service.startCurrentAccountOtpReAuth({
        sessionToken: signedIn.sessionToken,
        identityId: signedIn.identity.id,
        channel: OtpChannel.Email,
        now: addSeconds(now, 20),
      }),
    ).rejects.toMatchObject({
      code: UniAuthErrorCode.SessionNotFound,
    })

    const challenge = await service.startOtpChallenge({
      purpose: VerificationPurpose.ReAuth,
      channel: OtpChannel.Email,
      target: 'pg-current-account-reauth-disabled@example.com',
      secret: '555555',
      now: addSeconds(now, 5),
    })

    await expect(
      service.resendCurrentAccountOtpReAuth({
        sessionToken: signedIn.sessionToken,
        verificationId: challenge.verificationId,
        now: addSeconds(now, 20),
      }),
    ).rejects.toMatchObject({
      code: UniAuthErrorCode.SessionNotFound,
    })

    await expect(
      service.cancelCurrentAccountOtpReAuth({
        sessionToken: signedIn.sessionToken,
        verificationId: challenge.verificationId,
        now: addSeconds(now, 20),
      }),
    ).rejects.toMatchObject({
      code: UniAuthErrorCode.SessionNotFound,
    })

    await expect(
      service.confirmCurrentAccountPasswordByToken({
        sessionToken: signedIn.sessionToken,
        currentPassword: 'password',
        now: addSeconds(now, 20),
      }),
    ).rejects.toMatchObject({
      code: UniAuthErrorCode.SessionNotFound,
    })

    await expect(
      service.getCurrentAccountReAuthStatus({
        sessionToken: signedIn.sessionToken,
        action: AuthPolicyAction.ChangePassword,
        now: addSeconds(now, 20),
      }),
    ).rejects.toMatchObject({
      code: UniAuthErrorCode.SessionNotFound,
    })

    await expect(
      service.assertCurrentAccountReAuth({
        sessionToken: signedIn.sessionToken,
        action: AuthPolicyAction.ChangePassword,
        now: addSeconds(now, 20),
      }),
    ).rejects.toMatchObject({
      code: UniAuthErrorCode.SessionNotFound,
    })
  })
})
