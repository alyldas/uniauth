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
import { createInMemoryAuthKit } from '../../src/testing'
import { assertion, now } from './support.js'

describe('DefaultAuthService current-account re-auth helpers', () => {
  it('starts current-account OTP re-auth from an owned verified identity and composes with sensitive actions', async () => {
    const { service, emailSender, store } = createInMemoryAuthKit({
      policy: createDefaultAuthPolicy({
        requireReAuthFor: [AuthPolicyAction.Unlink],
      }),
    })
    const signedIn = await service.signIn({
      assertion: assertion({
        providerUserId: 'current-account-reauth-email',
        email: 'current-account-reauth@example.com',
        emailVerified: true,
      }),
      now,
    })
    const linked = await service.link({
      userId: signedIn.user.id,
      assertion: assertion({
        provider: 'github',
        providerUserId: 'current-account-reauth-github',
        email: 'current-account-reauth@example.com',
        emailVerified: true,
      }),
      now: addSeconds(now, 5),
    })

    const challenge = await service.startCurrentAccountOtpReAuth({
      sessionToken: signedIn.sessionToken,
      identityId: signedIn.identity.id,
      channel: OtpChannel.Email,
      secret: '654321',
      now: addSeconds(now, 10),
      metadata: { source: 'current-account-reauth' },
    })

    expect(challenge).toMatchObject({
      delivery: OtpChannel.Email,
    })
    expect(emailSender.listMessages()[0]).toMatchObject({
      to: 'current-account-reauth@example.com',
      text: 'Your sign-in code is 654321.',
    })

    const verification = await service.finishOtpChallenge({
      verificationId: challenge.verificationId,
      secret: '654321',
      purpose: VerificationPurpose.ReAuth,
      channel: OtpChannel.Email,
      now: addSeconds(now, 11),
    })

    expect(verification.consumedAt).toEqual(addSeconds(now, 11))
    const reAuthenticatedAt = verification.consumedAt ?? addSeconds(now, 11)

    await service.unlinkCurrentIdentityByToken({
      sessionToken: signedIn.sessionToken,
      identityId: linked.identity.id,
      reAuthenticatedAt,
      now: addSeconds(now, 11),
    })

    expect(store.listAuditEvents().map((event) => event.type)).toEqual(
      expect.arrayContaining([
        AuditEventType.VerificationCreated,
        AuditEventType.VerificationConsumed,
        AuditEventType.IdentityUnlinked,
      ]),
    )
  })

  it('supports phone current-account OTP re-auth and rejects foreign or unsupported identities', async () => {
    const { service, smsSender } = createInMemoryAuthKit()
    const alice = await service.signIn({
      assertion: assertion({
        providerUserId: 'current-account-reauth-owner',
        email: 'current-account-reauth-owner@example.com',
        emailVerified: true,
      }),
      now,
    })
    const phoneIdentity = await service.link({
      userId: alice.user.id,
      assertion: {
        provider: 'phone-otp',
        providerUserId: '+15550000001',
        phone: '+15550000001',
        phoneVerified: true,
      },
      now: addSeconds(now, 1),
    })
    const bob = await service.signIn({
      assertion: assertion({
        providerUserId: 'current-account-reauth-foreign',
        email: 'current-account-reauth-foreign@example.com',
        emailVerified: true,
      }),
      now: addSeconds(now, 5),
    })

    await service.startCurrentAccountOtpReAuth({
      sessionToken: alice.sessionToken,
      identityId: phoneIdentity.identity.id,
      channel: OtpChannel.Phone,
      secret: '222222',
      now: addSeconds(now, 9),
    })

    expect(smsSender.listMessages()[0]).toMatchObject({
      to: '+15550000001',
      text: 'Your sign-in code is 222222.',
    })

    await expect(
      service.startCurrentAccountOtpReAuth({
        sessionToken: alice.sessionToken,
        identityId: bob.identity.id,
        channel: OtpChannel.Email,
        now: addSeconds(now, 10),
      }),
    ).rejects.toMatchObject({
      code: UniAuthErrorCode.InvalidInput,
    })

    await expect(
      service.startCurrentAccountOtpReAuth({
        sessionToken: alice.sessionToken,
        identityId: alice.identity.id,
        channel: OtpChannel.Phone,
        now: addSeconds(now, 10),
      }),
    ).rejects.toMatchObject({
      code: UniAuthErrorCode.InvalidInput,
    })
  })

  it('confirms the current account password on the trusted session boundary without writing audit noise', async () => {
    const { service, store } = createInMemoryAuthKit({
      policy: createDefaultAuthPolicy({
        requireReAuthFor: [AuthPolicyAction.SetPassword, AuthPolicyAction.ChangePassword],
      }),
    })
    const signedIn = await service.signIn({
      assertion: assertion({
        providerUserId: 'current-account-password-reauth',
        email: 'current-account-password-reauth@example.com',
        emailVerified: true,
      }),
      now,
    })

    await service.setCurrentAccountPasswordByToken({
      sessionToken: signedIn.sessionToken,
      password: 'first-password',
      reAuthenticatedAt: addSeconds(now, 5),
      now: addSeconds(now, 5),
    })

    const auditCountBeforeConfirmation = store.listAuditEvents().length
    const confirmation = await service.confirmCurrentAccountPasswordByToken({
      sessionToken: signedIn.sessionToken,
      currentPassword: 'first-password',
      now: addSeconds(now, 20),
    })

    expect(confirmation).toEqual({
      userId: signedIn.user.id,
      reAuthenticatedAt: addSeconds(now, 20),
    })
    expect(store.listAuditEvents()).toHaveLength(auditCountBeforeConfirmation)

    await service.changeCurrentAccountPasswordByToken({
      sessionToken: signedIn.sessionToken,
      currentPassword: 'first-password',
      newPassword: 'second-password',
      reAuthenticatedAt: confirmation.reAuthenticatedAt,
      now: addSeconds(now, 20),
    })

    await expect(
      service.signInWithPassword({
        email: 'current-account-password-reauth@example.com',
        password: 'second-password',
        now: addSeconds(now, 21),
      }),
    ).resolves.toMatchObject({
      user: { id: signedIn.user.id },
    })
  })

  it('keeps current-account password re-auth neutral for wrong or missing password credentials', async () => {
    const { service } = createInMemoryAuthKit()
    const withPassword = await service.signIn({
      assertion: assertion({
        providerUserId: 'current-account-password-neutral',
        email: 'current-account-password-neutral@example.com',
        emailVerified: true,
      }),
      now,
    })

    await service.setCurrentAccountPasswordByToken({
      sessionToken: withPassword.sessionToken,
      password: 'first-password',
      reAuthenticatedAt: addSeconds(now, 5),
      now: addSeconds(now, 5),
    })

    await expect(
      service.confirmCurrentAccountPasswordByToken({
        sessionToken: withPassword.sessionToken,
        currentPassword: 'wrong-password',
        now: addSeconds(now, 10),
      }),
    ).rejects.toMatchObject({
      code: UniAuthErrorCode.InvalidCredentials,
    })

    const withoutPassword = await service.signIn({
      assertion: assertion({
        providerUserId: 'current-account-password-missing',
        email: 'current-account-password-missing@example.com',
        emailVerified: true,
      }),
      now: addSeconds(now, 20),
    })

    await expect(
      service.confirmCurrentAccountPasswordByToken({
        sessionToken: withoutPassword.sessionToken,
        currentPassword: 'missing-password',
        now: addSeconds(now, 21),
      }),
    ).rejects.toMatchObject({
      code: UniAuthErrorCode.InvalidCredentials,
    })
  })

  it('keeps stale disabled-user current-account re-auth helpers neutral', async () => {
    const { service, store } = createInMemoryAuthKit()
    const signedIn = await service.signIn({
      assertion: assertion({
        providerUserId: 'current-account-reauth-disabled',
        email: 'current-account-reauth-disabled@example.com',
        emailVerified: true,
      }),
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

  it('uses the runtime clock for current-account re-auth helpers when now is omitted', async () => {
    const runtimeNow = addSeconds(now, 30)
    const { service, emailSender } = createInMemoryAuthKit({
      clock: { now: () => runtimeNow },
    })
    const signedIn = await service.signIn({
      assertion: assertion({
        providerUserId: 'current-account-reauth-no-now',
        email: 'current-account-reauth-no-now@example.com',
        emailVerified: true,
      }),
      now,
    })

    const challenge = await service.startCurrentAccountOtpReAuth({
      sessionToken: signedIn.sessionToken,
      identityId: signedIn.identity.id,
      channel: OtpChannel.Email,
      secret: '333333',
    })
    const verification = await service.getVerification(challenge.verificationId)

    expect(verification.createdAt).toEqual(runtimeNow)
    expect(emailSender.listMessages()[0]).toMatchObject({
      to: 'current-account-reauth-no-now@example.com',
      text: 'Your sign-in code is 333333.',
    })

    await service.setCurrentAccountPasswordByToken({
      sessionToken: signedIn.sessionToken,
      password: 'first-password',
      reAuthenticatedAt: runtimeNow,
      now: runtimeNow,
    })

    await expect(
      service.confirmCurrentAccountPasswordByToken({
        sessionToken: signedIn.sessionToken,
        currentPassword: 'first-password',
      }),
    ).resolves.toEqual({
      userId: signedIn.user.id,
      reAuthenticatedAt: runtimeNow,
    })
  })
})
