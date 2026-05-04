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

    const verification = await service.finishOtpChallenge({
      verificationId: challenge.verificationId,
      secret: '654321',
      purpose: VerificationPurpose.ReAuth,
      channel: OtpChannel.Email,
      now: addSeconds(now, 11),
    })
    const reAuthenticatedAt = verification.consumedAt ?? addSeconds(now, 11)

    await service.unlinkCurrentIdentityByToken({
      sessionToken: signedIn.sessionToken,
      identityId: linked.identity.id,
      reAuthenticatedAt,
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

    await expect(
      service.confirmCurrentAccountPasswordByToken({
        sessionToken: signedIn.sessionToken,
        currentPassword: 'password',
        now: addSeconds(now, 20),
      }),
    ).rejects.toMatchObject({
      code: UniAuthErrorCode.SessionNotFound,
    })
  })
})
