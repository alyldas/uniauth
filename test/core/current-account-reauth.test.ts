import { describe, expect, it } from 'vitest'
import {
  AuditEventType,
  AuthPolicyAction,
  DefaultAuthService,
  OtpChannel,
  UniAuthErrorCode,
  VerificationPurpose,
  addSeconds,
  createDefaultAuthPolicy,
} from '../../src'
import { createInMemoryAuthKit } from '../../src/testing'
import { assertion, now } from './support.js'

describe('DefaultAuthService current-account re-auth helpers', () => {
  it('rejects future re-auth markers in current-account status reads', async () => {
    const { service } = createInMemoryAuthKit({
      policy: createDefaultAuthPolicy({
        requireReAuthFor: [AuthPolicyAction.CloseAccount],
      }),
    })
    const signedIn = await service.signIn({
      assertion: assertion({
        providerUserId: 'current-account-reauth-status-future',
        email: 'current-account-reauth-status-future@example.com',
        emailVerified: true,
      }),
      now,
    })

    await expect(
      service.getCurrentAccountReAuthStatus({
        sessionToken: signedIn.sessionToken,
        action: AuthPolicyAction.CloseAccount,
        reAuthenticatedAt: addSeconds(now, 60),
        now,
      }),
    ).rejects.toMatchObject({ code: UniAuthErrorCode.InvalidInput })
  })

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

    const confirmation = await service.finishCurrentAccountOtpReAuth({
      sessionToken: signedIn.sessionToken,
      verificationId: challenge.verificationId,
      secret: '654321',
      now: addSeconds(now, 11),
    })

    expect(confirmation).toEqual({
      currentSessionId: signedIn.session.id,
      userId: signedIn.user.id,
      reAuthenticatedAt: addSeconds(now, 11),
    })

    await service.unlinkCurrentIdentityByToken({
      sessionToken: signedIn.sessionToken,
      identityId: linked.identity.id,
      reAuthenticatedAt: confirmation.reAuthenticatedAt,
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

    const challenge = await service.startCurrentAccountOtpReAuth({
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

    const resent = await service.resendCurrentAccountOtpReAuth({
      sessionToken: alice.sessionToken,
      verificationId: challenge.verificationId,
      secret: '222223',
      now: addSeconds(now, 9),
    })

    expect(smsSender.listMessages()[1]).toMatchObject({
      to: '+15550000001',
      text: 'Your sign-in code is 222223.',
    })

    await service.cancelCurrentAccountOtpReAuth({
      sessionToken: alice.sessionToken,
      verificationId: resent.verificationId,
      now: addSeconds(now, 10),
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

  it('resends and cancels current-account OTP re-auth on the trusted session boundary', async () => {
    const { service, emailSender, store } = createInMemoryAuthKit()
    const signedIn = await service.signIn({
      assertion: assertion({
        providerUserId: 'current-account-reauth-resend-owner',
        email: 'current-account-reauth-resend@example.com',
        emailVerified: true,
      }),
      now,
    })

    const challenge = await service.startCurrentAccountOtpReAuth({
      sessionToken: signedIn.sessionToken,
      identityId: signedIn.identity.id,
      channel: OtpChannel.Email,
      secret: '111111',
      now: addSeconds(now, 10),
      metadata: { source: 'current-account-reauth-start' },
    })

    const resent = await service.resendCurrentAccountOtpReAuth({
      sessionToken: signedIn.sessionToken,
      verificationId: challenge.verificationId,
      secret: '222222',
      ttlSeconds: 120,
      now: addSeconds(now, 20),
      metadata: { source: 'current-account-reauth-resend' },
    })

    expect(resent.verificationId).not.toBe(challenge.verificationId)
    expect(emailSender.listMessages()[1]).toMatchObject({
      to: 'current-account-reauth-resend@example.com',
      text: 'Your sign-in code is 222222.',
      metadata: {
        verificationId: resent.verificationId,
        purpose: VerificationPurpose.ReAuth,
        delivery: OtpChannel.Email,
      },
    })
    expect(store.listVerifications()).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          id: challenge.verificationId,
          expiresAt: addSeconds(now, 20),
        }),
        expect.objectContaining({
          id: resent.verificationId,
          purpose: VerificationPurpose.ReAuth,
          target: 'current-account-reauth-resend@example.com',
          metadata: expect.objectContaining({
            requestMetadata: { source: 'current-account-reauth-resend' },
          }),
        }),
      ]),
    )

    const cancelled = await service.cancelCurrentAccountOtpReAuth({
      sessionToken: signedIn.sessionToken,
      verificationId: resent.verificationId,
      now: addSeconds(now, 21),
      metadata: { source: 'current-account-reauth-cancel' },
    })

    expect(cancelled).toMatchObject({
      id: resent.verificationId,
      expiresAt: addSeconds(now, 21),
    })
    expect(store.listAuditEvents()).toEqual(
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
            requestMetadata: { source: 'current-account-reauth-cancel' },
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

  it('keeps current-account OTP re-auth resend and cancellation neutral for foreign or non-re-auth challenges', async () => {
    const { service } = createInMemoryAuthKit()
    const alice = await service.signIn({
      assertion: assertion({
        providerUserId: 'current-account-reauth-neutral-owner',
        email: 'current-account-reauth-neutral-owner@example.com',
        emailVerified: true,
      }),
      now,
    })
    const bob = await service.signIn({
      assertion: assertion({
        providerUserId: 'current-account-reauth-neutral-foreign',
        email: 'current-account-reauth-neutral-foreign@example.com',
        emailVerified: true,
      }),
      now: addSeconds(now, 1),
    })
    const aliceSecondSession = await service.signIn({
      assertion: assertion({
        providerUserId: 'current-account-reauth-neutral-owner',
        email: 'current-account-reauth-neutral-owner@example.com',
        emailVerified: true,
      }),
      now: addSeconds(now, 2),
    })

    const ownedChallenge = await service.startCurrentAccountOtpReAuth({
      sessionToken: alice.sessionToken,
      identityId: alice.identity.id,
      channel: OtpChannel.Email,
      secret: '333333',
      now: addSeconds(now, 10),
    })
    const missingMetadataChallenge = await service.startOtpChallenge({
      purpose: VerificationPurpose.ReAuth,
      channel: OtpChannel.Email,
      target: 'current-account-reauth-neutral-owner@example.com',
      secret: '555555',
      now: addSeconds(now, 11),
    })
    const malformedMetadataChallenge = await service.startOtpChallenge({
      purpose: VerificationPurpose.ReAuth,
      channel: OtpChannel.Email,
      target: 'current-account-reauth-neutral-owner@example.com',
      secret: '666666',
      now: addSeconds(now, 11),
      metadata: {
        currentAccountOtpReAuth: {
          userId: 1,
          sessionId: alice.session.id,
          channel: OtpChannel.Email,
        },
      },
    })
    const signInChallenge = await service.startOtpChallenge({
      purpose: VerificationPurpose.SignIn,
      channel: OtpChannel.Email,
      target: 'current-account-reauth-neutral-owner@example.com',
      secret: '444444',
      now: addSeconds(now, 11),
    })

    await expect(
      service.finishOtpChallenge({
        verificationId: ownedChallenge.verificationId,
        secret: '333333',
        purpose: VerificationPurpose.ReAuth,
        channel: OtpChannel.Email,
        now: addSeconds(now, 20),
      }),
    ).rejects.toMatchObject({
      code: UniAuthErrorCode.InvalidInput,
    })

    for (const verificationId of [
      missingMetadataChallenge.verificationId,
      malformedMetadataChallenge.verificationId,
    ]) {
      await expect(
        service.finishCurrentAccountOtpReAuth({
          sessionToken: alice.sessionToken,
          verificationId,
          secret: '555555',
          now: addSeconds(now, 20),
        }),
      ).rejects.toMatchObject({
        code: UniAuthErrorCode.VerificationNotFound,
      })
    }

    await expect(
      service.resendCurrentAccountOtpReAuth({
        sessionToken: aliceSecondSession.sessionToken,
        verificationId: ownedChallenge.verificationId,
        now: addSeconds(now, 20),
      }),
    ).rejects.toMatchObject({
      code: UniAuthErrorCode.VerificationNotFound,
    })

    await expect(
      service.finishCurrentAccountOtpReAuth({
        sessionToken: aliceSecondSession.sessionToken,
        verificationId: ownedChallenge.verificationId,
        secret: '333333',
        now: addSeconds(now, 20),
      }),
    ).rejects.toMatchObject({
      code: UniAuthErrorCode.VerificationNotFound,
    })

    await expect(
      service.cancelCurrentAccountOtpReAuth({
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

  it('rethrows unexpected verification lookup failures from current-account OTP re-auth management helpers', async () => {
    const {
      service: setupService,
      store,
      emailSender,
      smsSender,
      rateLimiter,
      passwordHasher,
    } = createInMemoryAuthKit()
    const signedIn = await setupService.signIn({
      assertion: assertion({
        providerUserId: 'current-account-reauth-verification-lookup-failure',
        email: 'current-account-reauth-verification-lookup-failure@example.com',
        emailVerified: true,
      }),
      now,
    })
    const challenge = await setupService.startCurrentAccountOtpReAuth({
      sessionToken: signedIn.sessionToken,
      identityId: signedIn.identity.id,
      channel: OtpChannel.Email,
      secret: '777777',
      now: addSeconds(now, 5),
    })
    const lookupFailure = new Error('verification lookup failed')
    const service = new DefaultAuthService({
      repos: {
        userRepo: store.userRepo,
        identityRepo: store.identityRepo,
        credentialRepo: store.credentialRepo,
        verificationRepo: {
          ...store.verificationRepo,
          findById: async () => {
            throw lookupFailure
          },
          findByIdForUpdate: async () => {
            throw lookupFailure
          },
        },
        sessionRepo: store.sessionRepo,
        auditLogRepo: store.auditLogRepo,
      },
      emailSender,
      smsSender,
      rateLimiter,
      passwordHasher,
    })

    await expect(
      service.resendCurrentAccountOtpReAuth({
        sessionToken: signedIn.sessionToken,
        verificationId: challenge.verificationId,
        now: addSeconds(now, 10),
      }),
    ).rejects.toBe(lookupFailure)
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
      currentSessionId: signedIn.session.id,
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

  it('keeps current-account recent-auth status and assert helpers aligned with token-based password actions', async () => {
    const { service, store } = createInMemoryAuthKit({
      policy: createDefaultAuthPolicy({
        requireReAuthFor: [AuthPolicyAction.SetPassword, AuthPolicyAction.ChangePassword],
      }),
    })
    const signedIn = await service.signIn({
      assertion: assertion({
        providerUserId: 'current-account-recent-auth-status',
        email: 'current-account-recent-auth-status@example.com',
        emailVerified: true,
      }),
      now,
    })

    await service.setCurrentAccountPasswordByToken({
      sessionToken: signedIn.sessionToken,
      password: 'first-password',
      reAuthenticatedAt: addSeconds(now, 1),
      now: addSeconds(now, 1),
    })

    const auditCountBeforeStatus = store.listAuditEvents().length
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
    expect(store.listAuditEvents()).toHaveLength(auditCountBeforeStatus)

    await expect(
      service.assertCurrentAccountReAuth({
        sessionToken: signedIn.sessionToken,
        action: AuthPolicyAction.ChangePassword,
        now: addSeconds(now, 10),
      }),
    ).rejects.toMatchObject({
      code: UniAuthErrorCode.ReAuthRequired,
    })

    expect(store.listAuditEvents()).toEqual(
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

    await expect(
      service.getCurrentAccountReAuthStatus({
        sessionToken: signedIn.sessionToken,
        action: AuthPolicyAction.ChangePassword,
        reAuthenticatedAt: confirmation.reAuthenticatedAt,
        now: addSeconds(now, 20),
      }),
    ).resolves.toEqual({
      currentSessionId: signedIn.session.id,
      userId: signedIn.user.id,
      action: AuthPolicyAction.ChangePassword,
      required: false,
      checkedAt: addSeconds(now, 20),
      reAuthenticatedAt: addSeconds(now, 20),
    })

    const assertionResult = await service.assertCurrentAccountReAuth({
      sessionToken: signedIn.sessionToken,
      action: AuthPolicyAction.ChangePassword,
      reAuthenticatedAt: confirmation.reAuthenticatedAt,
      now: addSeconds(now, 20),
    })

    expect(assertionResult).toEqual({
      currentSessionId: signedIn.session.id,
      userId: signedIn.user.id,
      action: AuthPolicyAction.ChangePassword,
      checkedAt: addSeconds(now, 20),
      reAuthenticatedAt: addSeconds(now, 20),
    })

    await expect(
      service.changeCurrentAccountPasswordByToken({
        sessionToken: signedIn.sessionToken,
        currentPassword: 'first-password',
        newPassword: 'second-password',
        reAuthenticatedAt: addSeconds(now, 20),
        now: addSeconds(now, 20),
      }),
    ).resolves.toMatchObject({
      subject: 'current-account-recent-auth-status@example.com',
    })
  })

  it('rejects non-plain current-account OTP re-auth request metadata', async () => {
    const { service } = createInMemoryAuthKit()
    const signedIn = await service.signIn({
      assertion: assertion({
        providerUserId: 'current-account-reauth-request-metadata',
        email: 'current-account-reauth-request-metadata@example.com',
        emailVerified: true,
      }),
      now,
    })

    await expect(
      service.startCurrentAccountOtpReAuth({
        sessionToken: signedIn.sessionToken,
        identityId: signedIn.identity.id,
        channel: OtpChannel.Email,
        metadata: ['not-a-record'],
        now: addSeconds(now, 1),
      } as unknown as Parameters<typeof service.startCurrentAccountOtpReAuth>[0]),
    ).rejects.toMatchObject({
      code: UniAuthErrorCode.InvalidInput,
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
    const challenge = await service.startCurrentAccountOtpReAuth({
      sessionToken: signedIn.sessionToken,
      identityId: signedIn.identity.id,
      channel: OtpChannel.Email,
      secret: '555555',
      now: addSeconds(now, 5),
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

    const resent = await service.resendCurrentAccountOtpReAuth({
      sessionToken: signedIn.sessionToken,
      verificationId: challenge.verificationId,
      secret: '444444',
    })
    const resentVerification = await service.getVerification(resent.verificationId)

    expect(resentVerification.createdAt).toEqual(runtimeNow)

    const cancelled = await service.cancelCurrentAccountOtpReAuth({
      sessionToken: signedIn.sessionToken,
      verificationId: resent.verificationId,
    })

    expect(cancelled.expiresAt).toEqual(runtimeNow)

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
      currentSessionId: signedIn.session.id,
      userId: signedIn.user.id,
      reAuthenticatedAt: runtimeNow,
    })

    await expect(
      service.getCurrentAccountReAuthStatus({
        sessionToken: signedIn.sessionToken,
        action: AuthPolicyAction.ChangePassword,
      }),
    ).resolves.toEqual({
      currentSessionId: signedIn.session.id,
      userId: signedIn.user.id,
      action: AuthPolicyAction.ChangePassword,
      required: false,
      checkedAt: runtimeNow,
    })
  })
})
