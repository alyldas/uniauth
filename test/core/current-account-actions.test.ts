import { describe, expect, it } from 'vitest'
import {
  AuditEventType,
  AuthPolicyAction,
  OtpChannel,
  PASSWORD_PROVIDER_ID,
  UniAuthErrorCode,
  VerificationPurpose,
  addSeconds,
  createDefaultAuthPolicy,
} from '../../src'
import { createInMemoryAuthKit } from '../../src/testing'
import { assertion, now } from './support.js'

describe('DefaultAuthService current-account action helpers', () => {
  it('revokes one owned session by trusted session token while preserving the current session', async () => {
    const { service } = createInMemoryAuthKit()
    const signedIn = await service.signIn({
      assertion: assertion({
        providerUserId: 'current-account-owned-session',
        email: 'current-account-owned-session@example.com',
        emailVerified: true,
      }),
      now,
    })
    const secondSession = await service.createSession({
      userId: signedIn.user.id,
      now: addSeconds(now, 10),
    })

    const result = await service.revokeOwnedSessionByToken({
      sessionToken: signedIn.sessionToken,
      targetSessionId: secondSession.session.id,
      now: addSeconds(now, 20),
    })

    expect(result).toEqual({
      currentSessionId: signedIn.session.id,
      revokedSessionId: secondSession.session.id,
      revokedCurrentSession: false,
    })
    await expect(
      service.resolveSession({
        sessionToken: secondSession.sessionToken,
        now: addSeconds(now, 21),
      }),
    ).rejects.toMatchObject({
      code: UniAuthErrorCode.SessionNotFound,
    })
    await expect(
      service.resolveSession({
        sessionToken: signedIn.sessionToken,
        now: addSeconds(now, 21),
      }),
    ).resolves.toMatchObject({
      id: signedIn.session.id,
    })
  })

  it('can revoke the current session through the selected-session helper without an explicit now override', async () => {
    const { service } = createInMemoryAuthKit({
      clock: { now: () => now },
    })
    const signedIn = await service.signIn({
      assertion: assertion({
        providerUserId: 'current-account-revoke-current-session',
        email: 'current-account-revoke-current-session@example.com',
        emailVerified: true,
      }),
    })

    const result = await service.revokeOwnedSessionByToken({
      sessionToken: signedIn.sessionToken,
      targetSessionId: signedIn.session.id,
    })

    expect(result).toEqual({
      currentSessionId: signedIn.session.id,
      revokedSessionId: signedIn.session.id,
      revokedCurrentSession: true,
    })
    await expect(
      service.resolveSession({
        sessionToken: signedIn.sessionToken,
        now,
      }),
    ).rejects.toMatchObject({
      code: UniAuthErrorCode.SessionNotFound,
    })
  })

  it('keeps selected-session revocation neutral for foreign sessions', async () => {
    const { service } = createInMemoryAuthKit()
    const alice = await service.signIn({
      assertion: assertion({
        providerUserId: 'current-account-revoke-foreign-owner',
        email: 'current-account-revoke-foreign-owner@example.com',
        emailVerified: true,
      }),
      now,
    })
    const bob = await service.signIn({
      assertion: assertion({
        providerUserId: 'current-account-revoke-foreign-target',
        email: 'current-account-revoke-foreign-target@example.com',
        emailVerified: true,
      }),
      now: addSeconds(now, 10),
    })

    await expect(
      service.revokeOwnedSessionByToken({
        sessionToken: alice.sessionToken,
        targetSessionId: bob.session.id,
        now: addSeconds(now, 20),
      }),
    ).rejects.toMatchObject({
      code: UniAuthErrorCode.SessionNotFound,
    })
  })

  it('updates the current account profile by trusted session token', async () => {
    const { service } = createInMemoryAuthKit({
      policy: createDefaultAuthPolicy({
        requireReAuthFor: [AuthPolicyAction.UpdateProfile],
      }),
    })
    const signedIn = await service.signIn({
      assertion: assertion({
        providerUserId: 'current-account-profile',
        email: 'current-account-profile@example.com',
        emailVerified: true,
        phone: '+15550000001',
        phoneVerified: true,
        displayName: 'Before',
        metadata: { externalProfileId: 'profile-1' },
      }),
      now,
    })
    const originalIdentities = await service.getUserIdentities(signedIn.user.id)
    const originalSessions = await service.getUserSessions(signedIn.user.id)

    await expect(
      service.updateCurrentAccountProfileByToken({
        sessionToken: signedIn.sessionToken,
        displayName: 'Updated',
        now: addSeconds(now, 10),
      }),
    ).rejects.toMatchObject({
      code: UniAuthErrorCode.ReAuthRequired,
    })

    const updatedAt = addSeconds(now, 20)
    const updated = await service.updateCurrentAccountProfileByToken({
      sessionToken: signedIn.sessionToken,
      displayName: '  Updated Name  ',
      reAuthenticatedAt: updatedAt,
      now: updatedAt,
      metadata: { source: 'settings' },
    })

    expect(updated).toMatchObject({
      id: signedIn.user.id,
      displayName: 'Updated Name',
      email: 'current-account-profile@example.com',
      phone: '+15550000001',
      updatedAt,
    })
    await expect(service.getUser(signedIn.user.id)).resolves.toMatchObject({
      displayName: 'Updated Name',
      email: 'current-account-profile@example.com',
      phone: '+15550000001',
    })
    expect(await service.getUserIdentities(signedIn.user.id)).toEqual(originalIdentities)
    expect(await service.getUserSessions(signedIn.user.id)).toEqual(originalSessions)
    await expect(service.getAuditEvents({ userId: signedIn.user.id })).resolves.toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          type: AuditEventType.AccountProfileUpdated,
          sessionId: signedIn.session.id,
          metadata: {
            changedFields: ['displayName'],
            requestMetadata: { source: 'settings' },
          },
        }),
      ]),
    )
  })

  it('normalizes blank current-account profile display names and rejects empty updates', async () => {
    const { service } = createInMemoryAuthKit({
      clock: { now: () => now },
    })
    const signedIn = await service.signIn({
      assertion: assertion({
        providerUserId: 'current-account-profile-blank',
        email: 'current-account-profile-blank@example.com',
        emailVerified: true,
        displayName: 'Before',
      }),
    })

    const cleared = await service.updateCurrentAccountProfileByToken({
      sessionToken: signedIn.sessionToken,
      displayName: '   ',
    })

    expect(cleared).toMatchObject({
      id: signedIn.user.id,
      updatedAt: now,
    })
    expect(cleared.displayName).toBeUndefined()
    const clearedFromUndefined = await service.updateCurrentAccountProfileByToken({
      sessionToken: signedIn.sessionToken,
      displayName: undefined as unknown as string,
    })

    expect(clearedFromUndefined.displayName).toBeUndefined()
    await expect(
      service.updateCurrentAccountProfileByToken({
        sessionToken: signedIn.sessionToken,
      }),
    ).rejects.toMatchObject({
      code: UniAuthErrorCode.InvalidInput,
    })
  })

  it('starts, resends, and finishes current-account email changes by trusted session token', async () => {
    const { service, emailSender } = createInMemoryAuthKit({
      policy: createDefaultAuthPolicy({
        requireReAuthFor: [AuthPolicyAction.UpdateContact],
      }),
    })
    const signedIn = await service.signIn({
      assertion: assertion({
        providerUserId: 'current-account-email-change',
        email: 'old-current-account-email-change@example.com',
        emailVerified: true,
        phone: '+15550000003',
        phoneVerified: true,
      }),
      now,
    })
    const originalIdentities = await service.getUserIdentities(signedIn.user.id)

    await expect(
      service.startCurrentAccountContactChange({
        sessionToken: signedIn.sessionToken,
        channel: OtpChannel.Email,
        target: 'new-current-account-email-change@example.com',
        secret: '111111',
        now: addSeconds(now, 10),
      }),
    ).rejects.toMatchObject({
      code: UniAuthErrorCode.ReAuthRequired,
    })

    const first = await service.startCurrentAccountContactChange({
      sessionToken: signedIn.sessionToken,
      channel: OtpChannel.Email,
      target: ' New-Current-Account-Email-Change@Example.COM ',
      secret: '111111',
      reAuthenticatedAt: addSeconds(now, 20),
      now: addSeconds(now, 20),
      metadata: { source: 'settings' },
    })
    const resent = await service.resendCurrentAccountContactChange({
      sessionToken: signedIn.sessionToken,
      verificationId: first.verificationId,
      secret: '222222',
      now: addSeconds(now, 30),
      metadata: { source: 'settings-resend' },
    })

    expect(emailSender.listMessages()).toEqual([
      expect.objectContaining({
        to: 'new-current-account-email-change@example.com',
        metadata: expect.objectContaining({
          purpose: VerificationPurpose.ContactChange,
          delivery: OtpChannel.Email,
        }),
      }),
      expect.objectContaining({
        to: 'new-current-account-email-change@example.com',
        metadata: expect.objectContaining({
          purpose: VerificationPurpose.ContactChange,
          delivery: OtpChannel.Email,
        }),
      }),
    ])
    await expect(
      service.finishCurrentAccountContactChange({
        sessionToken: signedIn.sessionToken,
        verificationId: first.verificationId,
        secret: '111111',
        now: addSeconds(now, 35),
      }),
    ).rejects.toMatchObject({
      code: UniAuthErrorCode.VerificationExpired,
    })

    const updated = await service.finishCurrentAccountContactChange({
      sessionToken: signedIn.sessionToken,
      verificationId: resent.verificationId,
      secret: '222222',
      now: addSeconds(now, 40),
      metadata: { source: 'settings-finish' },
    })

    expect(updated).toMatchObject({
      id: signedIn.user.id,
      email: 'new-current-account-email-change@example.com',
      phone: '+15550000003',
      updatedAt: addSeconds(now, 40),
    })
    expect(await service.getUserIdentities(signedIn.user.id)).toEqual(originalIdentities)
    await expect(service.getAuditEvents({ userId: signedIn.user.id })).resolves.toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          type: AuditEventType.AccountContactUpdated,
          sessionId: signedIn.session.id,
          metadata: {
            verificationId: resent.verificationId,
            channel: OtpChannel.Email,
            changedFields: ['email'],
            requestMetadata: { source: 'settings-finish' },
          },
        }),
      ]),
    )
  })

  it('keeps current-account contact change ownership neutral and supports cancellation', async () => {
    const { service } = createInMemoryAuthKit()
    const alice = await service.signIn({
      assertion: assertion({
        providerUserId: 'current-account-contact-change-owner',
        email: 'current-account-contact-change-owner@example.com',
        emailVerified: true,
      }),
      now,
    })
    const bob = await service.signIn({
      assertion: assertion({
        providerUserId: 'current-account-contact-change-foreign',
        email: 'current-account-contact-change-foreign@example.com',
        emailVerified: true,
      }),
      now: addSeconds(now, 1),
    })
    const aliceSecondSession = await service.signIn({
      assertion: assertion({
        providerUserId: 'current-account-contact-change-owner',
        email: 'current-account-contact-change-owner@example.com',
        emailVerified: true,
      }),
      now: addSeconds(now, 2),
    })
    const started = await service.startCurrentAccountContactChange({
      sessionToken: alice.sessionToken,
      channel: OtpChannel.Phone,
      target: '+1 (555) 000-0004',
      secret: '333333',
      now: addSeconds(now, 5),
    })

    await expect(
      service.finishCurrentAccountContactChange({
        sessionToken: bob.sessionToken,
        verificationId: started.verificationId,
        secret: '333333',
        now: addSeconds(now, 6),
      }),
    ).rejects.toMatchObject({
      code: UniAuthErrorCode.VerificationNotFound,
    })

    await expect(
      service.cancelCurrentAccountContactChange({
        sessionToken: aliceSecondSession.sessionToken,
        verificationId: started.verificationId,
        now: addSeconds(now, 6),
      }),
    ).rejects.toMatchObject({
      code: UniAuthErrorCode.VerificationNotFound,
    })

    await service.cancelCurrentAccountContactChange({
      sessionToken: alice.sessionToken,
      verificationId: started.verificationId,
      now: addSeconds(now, 7),
      metadata: { source: 'settings-cancel' },
    })
    await expect(
      service.finishCurrentAccountContactChange({
        sessionToken: alice.sessionToken,
        verificationId: started.verificationId,
        secret: '333333',
        now: addSeconds(now, 8),
      }),
    ).rejects.toMatchObject({
      code: UniAuthErrorCode.VerificationExpired,
    })
  })

  it('rejects invalid current-account contact change inputs before delivery', async () => {
    const { service, emailSender, smsSender } = createInMemoryAuthKit()
    const signedIn = await service.signIn({
      assertion: assertion({
        providerUserId: 'current-account-contact-change-invalid-inputs',
        email: 'current-account-contact-change-invalid-inputs@example.com',
        emailVerified: true,
        phone: '+15550000006',
        phoneVerified: true,
      }),
      now,
    })

    await expect(
      service.startCurrentAccountContactChange({
        sessionToken: signedIn.sessionToken,
        channel: 'push' as OtpChannel,
        target: 'new@example.com',
        now: addSeconds(now, 5),
      }),
    ).rejects.toMatchObject({
      code: UniAuthErrorCode.InvalidInput,
    })
    await expect(
      service.startCurrentAccountContactChange({
        sessionToken: signedIn.sessionToken,
        channel: OtpChannel.Email,
        target: ' CURRENT-ACCOUNT-CONTACT-CHANGE-INVALID-INPUTS@example.com ',
        now: addSeconds(now, 6),
      }),
    ).rejects.toMatchObject({
      code: UniAuthErrorCode.InvalidInput,
    })
    await expect(
      service.startCurrentAccountContactChange({
        sessionToken: signedIn.sessionToken,
        channel: OtpChannel.Phone,
        target: '+1 (555) 000-0006',
        now: addSeconds(now, 7),
      }),
    ).rejects.toMatchObject({
      code: UniAuthErrorCode.InvalidInput,
    })

    expect(emailSender.listMessages()).toHaveLength(0)
    expect(smsSender.listMessages()).toHaveLength(0)
  })

  it('keeps malformed current-account contact change verification ownership neutral', async () => {
    const { service } = createInMemoryAuthKit()
    const signedIn = await service.signIn({
      assertion: assertion({
        providerUserId: 'current-account-contact-change-malformed-metadata',
        email: 'current-account-contact-change-malformed-metadata@example.com',
        emailVerified: true,
      }),
      now,
    })
    const missingMetadata = await service.startOtpChallenge({
      purpose: VerificationPurpose.ContactChange,
      channel: OtpChannel.Email,
      target: 'missing-metadata@example.com',
      secret: '444444',
      now: addSeconds(now, 5),
    })
    const invalidMetadata = await service.startOtpChallenge({
      purpose: VerificationPurpose.ContactChange,
      channel: OtpChannel.Email,
      target: 'invalid-metadata@example.com',
      secret: '555555',
      now: addSeconds(now, 6),
      metadata: {
        currentAccountContactChange: {
          userId: 1,
          sessionId: signedIn.session.id,
          channel: OtpChannel.Email,
        },
      },
    })

    for (const verificationId of [missingMetadata.verificationId, invalidMetadata.verificationId]) {
      await expect(
        service.finishCurrentAccountContactChange({
          sessionToken: signedIn.sessionToken,
          verificationId,
          secret: '444444',
          now: addSeconds(now, 10),
        }),
      ).rejects.toMatchObject({
        code: UniAuthErrorCode.VerificationNotFound,
      })
    }
  })

  it('keeps non-contact verifications and adapter lookup failures on their expected paths', async () => {
    const { service, store } = createInMemoryAuthKit()
    const signedIn = await service.signIn({
      assertion: assertion({
        providerUserId: 'current-account-contact-change-wrong-verification',
        email: 'current-account-contact-change-wrong-verification@example.com',
        emailVerified: true,
      }),
      now,
    })
    const signInChallenge = await service.startOtpChallenge({
      purpose: VerificationPurpose.SignIn,
      channel: OtpChannel.Email,
      target: 'current-account-contact-change-wrong-verification@example.com',
      secret: '666666',
      now: addSeconds(now, 5),
    })

    await expect(
      service.finishCurrentAccountContactChange({
        sessionToken: signedIn.sessionToken,
        verificationId: signInChallenge.verificationId,
        secret: '666666',
        now: addSeconds(now, 10),
      }),
    ).rejects.toMatchObject({
      code: UniAuthErrorCode.VerificationNotFound,
    })
    await expect(
      service.cancelCurrentAccountContactChange({
        sessionToken: signedIn.sessionToken,
        verificationId: 'missing-contact-change' as typeof signInChallenge.verificationId,
        now: addSeconds(now, 11),
      }),
    ).rejects.toMatchObject({
      code: UniAuthErrorCode.VerificationNotFound,
    })

    const originalFindById = store.verificationRepo.findById
    store.verificationRepo.findById = async () => {
      throw new Error('verification lookup failed')
    }

    await expect(
      service.resendCurrentAccountContactChange({
        sessionToken: signedIn.sessionToken,
        verificationId: signInChallenge.verificationId,
        now: addSeconds(now, 12),
      }),
    ).rejects.toThrow('verification lookup failed')

    store.verificationRepo.findById = originalFindById
  })

  it('keeps expired and revoked current-account profile update contexts neutral', async () => {
    const { service } = createInMemoryAuthKit()
    const revoked = await service.signIn({
      assertion: assertion({
        providerUserId: 'current-account-profile-revoked',
        email: 'current-account-profile-revoked@example.com',
        emailVerified: true,
      }),
      now,
    })
    const expired = await service.signIn({
      assertion: assertion({
        providerUserId: 'current-account-profile-expired',
        email: 'current-account-profile-expired@example.com',
        emailVerified: true,
      }),
      sessionExpiresAt: addSeconds(now, 5),
      now,
    })

    await service.revokeCurrentSessionByToken({
      sessionToken: revoked.sessionToken,
      now: addSeconds(now, 5),
    })

    await expect(
      service.updateCurrentAccountProfileByToken({
        sessionToken: revoked.sessionToken,
        displayName: 'Updated',
        now: addSeconds(now, 10),
      }),
    ).rejects.toMatchObject({
      code: UniAuthErrorCode.SessionNotFound,
    })
    await expect(
      service.updateCurrentAccountProfileByToken({
        sessionToken: expired.sessionToken,
        displayName: 'Updated',
        now: addSeconds(now, 10),
      }),
    ).rejects.toMatchObject({
      code: UniAuthErrorCode.SessionNotFound,
    })
  })

  it('unlinks current-account identities by session token and preserves re-auth and last-identity rules', async () => {
    const { service } = createInMemoryAuthKit({
      policy: createDefaultAuthPolicy({
        requireReAuthFor: [AuthPolicyAction.Unlink],
      }),
    })
    const signedIn = await service.signIn({
      assertion: assertion({
        provider: 'email',
        providerUserId: 'current-account-unlink-email',
        email: 'current-account-unlink@example.com',
        emailVerified: true,
      }),
      now,
    })
    const linked = await service.link({
      userId: signedIn.user.id,
      assertion: assertion({
        provider: 'github',
        providerUserId: 'current-account-unlink-github',
        email: 'current-account-unlink@example.com',
        emailVerified: true,
      }),
      now: addSeconds(now, 5),
    })

    await expect(
      service.unlinkCurrentIdentityByToken({
        sessionToken: signedIn.sessionToken,
        identityId: linked.identity.id,
        now: addSeconds(now, 10),
      }),
    ).rejects.toMatchObject({
      code: UniAuthErrorCode.ReAuthRequired,
    })

    await service.unlinkCurrentIdentityByToken({
      sessionToken: signedIn.sessionToken,
      identityId: linked.identity.id,
      reAuthenticatedAt: addSeconds(now, 10),
      now: addSeconds(now, 10),
    })

    expect(await service.getUserIdentities(signedIn.user.id)).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          id: signedIn.identity.id,
          status: 'active',
        }),
        expect.objectContaining({
          id: linked.identity.id,
          status: 'disabled',
        }),
      ]),
    )

    await expect(
      service.unlinkCurrentIdentityByToken({
        sessionToken: signedIn.sessionToken,
        identityId: signedIn.identity.id,
        reAuthenticatedAt: addSeconds(now, 11),
        now: addSeconds(now, 11),
      }),
    ).rejects.toMatchObject({
      code: UniAuthErrorCode.LastIdentity,
    })
  })

  it('sets and changes a current-account password by trusted session token', async () => {
    const { service } = createInMemoryAuthKit({
      policy: createDefaultAuthPolicy({
        requireReAuthFor: [AuthPolicyAction.SetPassword, AuthPolicyAction.ChangePassword],
      }),
    })
    const signedIn = await service.signIn({
      assertion: assertion({
        provider: 'email',
        providerUserId: 'current-account-password',
        email: 'current-account-password@example.com',
        emailVerified: true,
      }),
      now,
    })

    await expect(
      service.setCurrentAccountPasswordByToken({
        sessionToken: signedIn.sessionToken,
        password: 'first-password',
        now: addSeconds(now, 10),
      }),
    ).rejects.toMatchObject({
      code: UniAuthErrorCode.ReAuthRequired,
    })

    const created = await service.setCurrentAccountPasswordByToken({
      sessionToken: signedIn.sessionToken,
      password: 'first-password',
      reAuthenticatedAt: addSeconds(now, 10),
      now: addSeconds(now, 10),
    })

    expect(created.type).toBe(PASSWORD_PROVIDER_ID)
    await expect(
      service.signInWithPassword({
        email: 'current-account-password@example.com',
        password: 'first-password',
        now: addSeconds(now, 11),
      }),
    ).resolves.toMatchObject({
      user: { id: signedIn.user.id },
    })

    await expect(
      service.changeCurrentAccountPasswordByToken({
        sessionToken: signedIn.sessionToken,
        currentPassword: 'first-password',
        newPassword: 'second-password',
        now: addSeconds(now, 20),
      }),
    ).rejects.toMatchObject({
      code: UniAuthErrorCode.ReAuthRequired,
    })

    await expect(
      service.changeCurrentAccountPasswordByToken({
        sessionToken: signedIn.sessionToken,
        currentPassword: 'wrong-password',
        newPassword: 'second-password',
        reAuthenticatedAt: addSeconds(now, 20),
        now: addSeconds(now, 20),
      }),
    ).rejects.toMatchObject({
      code: UniAuthErrorCode.InvalidCredentials,
    })

    const changed = await service.changeCurrentAccountPasswordByToken({
      sessionToken: signedIn.sessionToken,
      currentPassword: 'first-password',
      newPassword: 'second-password',
      reAuthenticatedAt: addSeconds(now, 21),
      now: addSeconds(now, 21),
    })

    expect(changed.subject).toBe('current-account-password@example.com')
    await expect(
      service.signInWithPassword({
        email: 'current-account-password@example.com',
        password: 'first-password',
        now: addSeconds(now, 22),
      }),
    ).rejects.toMatchObject({
      code: UniAuthErrorCode.InvalidCredentials,
    })
    await expect(
      service.signInWithPassword({
        email: 'current-account-password@example.com',
        password: 'second-password',
        now: addSeconds(now, 22),
      }),
    ).resolves.toMatchObject({
      user: { id: signedIn.user.id },
    })
  })

  it('rejects token-based password setup when the current account has no trusted email', async () => {
    const { service } = createInMemoryAuthKit()
    const signedIn = await service.signIn({
      assertion: {
        provider: 'telegram',
        providerUserId: 'current-account-password-no-email',
        displayName: 'No Email',
      },
      now,
    })

    await expect(
      service.setCurrentAccountPasswordByToken({
        sessionToken: signedIn.sessionToken,
        password: 'password',
        reAuthenticatedAt: now,
        now,
      }),
    ).rejects.toMatchObject({
      code: UniAuthErrorCode.InvalidInput,
    })
  })

  it('closes the current account by trusted session token after recent authentication', async () => {
    const { service, store } = createInMemoryAuthKit()
    const signedIn = await service.signIn({
      assertion: assertion({
        providerUserId: 'current-account-close',
        email: 'current-account-close@example.com',
        emailVerified: true,
      }),
      now,
    })
    const secondSession = await service.createSession({
      userId: signedIn.user.id,
      now: addSeconds(now, 5),
    })

    await expect(
      service.closeCurrentAccountByToken({
        sessionToken: signedIn.sessionToken,
        now: addSeconds(now, 10),
      }),
    ).rejects.toMatchObject({
      code: UniAuthErrorCode.ReAuthRequired,
    })

    const closedAt = addSeconds(now, 20)
    const result = await service.closeCurrentAccountByToken({
      sessionToken: signedIn.sessionToken,
      reAuthenticatedAt: closedAt,
      now: closedAt,
      metadata: { source: 'settings' },
    })

    expect(result.currentSessionId).toBe(signedIn.session.id)
    expect(result.revokedSessionIds).toEqual([signedIn.session.id, secondSession.session.id])
    expect(result.user).toMatchObject({
      id: signedIn.user.id,
      disabledAt: closedAt,
      updatedAt: closedAt,
    })
    await expect(store.userRepo.findById(signedIn.user.id)).resolves.toMatchObject({
      disabledAt: closedAt,
    })
    await expect(
      service.resolveSession({
        sessionToken: signedIn.sessionToken,
        now: addSeconds(closedAt, 1),
      }),
    ).rejects.toMatchObject({
      code: UniAuthErrorCode.SessionNotFound,
    })
    await expect(
      service.resolveSession({
        sessionToken: secondSession.sessionToken,
        now: addSeconds(closedAt, 1),
      }),
    ).rejects.toMatchObject({
      code: UniAuthErrorCode.SessionNotFound,
    })

    await expect(service.getAuditEvents({ userId: signedIn.user.id })).resolves.toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          type: AuditEventType.AccountClosed,
          userId: signedIn.user.id,
          sessionId: signedIn.session.id,
          metadata: {
            revokedSessionIds: [signedIn.session.id, secondSession.session.id],
            requestMetadata: { source: 'settings' },
          },
        }),
        expect.objectContaining({
          type: AuditEventType.SessionRevoked,
          sessionId: signedIn.session.id,
        }),
        expect.objectContaining({
          type: AuditEventType.SessionRevoked,
          sessionId: secondSession.session.id,
        }),
      ]),
    )
  })

  it('uses the runtime clock for current-account account closure when now is omitted', async () => {
    const { service } = createInMemoryAuthKit({
      clock: { now: () => now },
    })
    const signedIn = await service.signIn({
      assertion: assertion({
        providerUserId: 'current-account-close-no-now',
        email: 'current-account-close-no-now@example.com',
        emailVerified: true,
      }),
    })

    const result = await service.closeCurrentAccountByToken({
      sessionToken: signedIn.sessionToken,
      reAuthenticatedAt: now,
    })

    expect(result.user).toMatchObject({
      id: signedIn.user.id,
      disabledAt: now,
      updatedAt: now,
    })
    expect(result.revokedSessionIds).toEqual([signedIn.session.id])
  })

  it('keeps expired and revoked current-account account closure contexts neutral', async () => {
    const { service } = createInMemoryAuthKit()
    const revoked = await service.signIn({
      assertion: assertion({
        providerUserId: 'current-account-close-revoked',
        email: 'current-account-close-revoked@example.com',
        emailVerified: true,
      }),
      now,
    })
    const expired = await service.signIn({
      assertion: assertion({
        providerUserId: 'current-account-close-expired',
        email: 'current-account-close-expired@example.com',
        emailVerified: true,
      }),
      sessionExpiresAt: addSeconds(now, 5),
      now,
    })

    await service.revokeCurrentSessionByToken({
      sessionToken: revoked.sessionToken,
      now: addSeconds(now, 5),
    })

    await expect(
      service.closeCurrentAccountByToken({
        sessionToken: revoked.sessionToken,
        reAuthenticatedAt: addSeconds(now, 10),
        now: addSeconds(now, 10),
      }),
    ).rejects.toMatchObject({
      code: UniAuthErrorCode.SessionNotFound,
    })
    await expect(
      service.closeCurrentAccountByToken({
        sessionToken: expired.sessionToken,
        reAuthenticatedAt: addSeconds(now, 10),
        now: addSeconds(now, 10),
      }),
    ).rejects.toMatchObject({
      code: UniAuthErrorCode.SessionNotFound,
    })
  })

  it('uses the runtime clock and forwards metadata for current-account action helpers when now is omitted', async () => {
    const { service } = createInMemoryAuthKit({
      clock: { now: () => now },
      policy: createDefaultAuthPolicy({
        requireReAuthFor: [
          AuthPolicyAction.Unlink,
          AuthPolicyAction.SetPassword,
          AuthPolicyAction.ChangePassword,
          AuthPolicyAction.UpdateContact,
        ],
      }),
    })
    const signedIn = await service.signIn({
      assertion: assertion({
        provider: 'email',
        providerUserId: 'current-account-actions-no-now',
        email: 'current-account-actions-no-now@example.com',
        emailVerified: true,
      }),
    })
    const linked = await service.link({
      userId: signedIn.user.id,
      assertion: assertion({
        provider: 'github',
        providerUserId: 'current-account-actions-no-now-github',
        email: 'current-account-actions-no-now@example.com',
        emailVerified: true,
      }),
    })

    const created = await service.setCurrentAccountPasswordByToken({
      sessionToken: signedIn.sessionToken,
      password: 'first-password',
      reAuthenticatedAt: now,
      metadata: { source: 'current-account-set' },
    })
    const changed = await service.changeCurrentAccountPasswordByToken({
      sessionToken: signedIn.sessionToken,
      currentPassword: 'first-password',
      newPassword: 'second-password',
      reAuthenticatedAt: now,
      metadata: { source: 'current-account-change' },
    })
    const contactChange = await service.startCurrentAccountContactChange({
      sessionToken: signedIn.sessionToken,
      channel: OtpChannel.Email,
      target: 'current-account-actions-no-now-new@example.com',
      secret: '123456',
      reAuthenticatedAt: now,
      metadata: { source: 'current-account-contact-start' },
    })
    const updatedContact = await service.finishCurrentAccountContactChange({
      sessionToken: signedIn.sessionToken,
      verificationId: contactChange.verificationId,
      secret: '123456',
      metadata: { source: 'current-account-contact-finish' },
    })

    await service.unlinkCurrentIdentityByToken({
      sessionToken: signedIn.sessionToken,
      identityId: linked.identity.id,
      reAuthenticatedAt: now,
      metadata: { source: 'current-account-unlink' },
    })

    expect(created.metadata).toEqual({ source: 'current-account-set' })
    expect(changed.metadata).toEqual({ source: 'current-account-change' })
    expect(updatedContact).toMatchObject({
      id: signedIn.user.id,
      email: 'current-account-actions-no-now-new@example.com',
      updatedAt: now,
    })
    await expect(
      service.signInWithPassword({
        email: 'current-account-actions-no-now@example.com',
        password: 'second-password',
        now: addSeconds(now, 1),
      }),
    ).resolves.toMatchObject({
      user: { id: signedIn.user.id },
    })
  })

  it('rejects non-plain current-account request metadata and accepts null-prototype metadata', async () => {
    const { service, store } = createInMemoryAuthKit({
      policy: createDefaultAuthPolicy({
        requireReAuthFor: [AuthPolicyAction.UpdateProfile],
      }),
    })
    const signedIn = await service.signIn({
      assertion: assertion({
        providerUserId: 'current-account-request-metadata',
        email: 'current-account-request-metadata@example.com',
        emailVerified: true,
      }),
      now,
    })

    await expect(
      service.updateCurrentAccountProfileByToken({
        sessionToken: signedIn.sessionToken,
        displayName: 'Alice',
        reAuthenticatedAt: now,
        metadata: ['not-a-record'],
        now: addSeconds(now, 1),
      } as unknown as Parameters<typeof service.updateCurrentAccountProfileByToken>[0]),
    ).rejects.toMatchObject({
      code: UniAuthErrorCode.InvalidInput,
    })
    await expect(
      service.closeCurrentAccountByToken({
        sessionToken: signedIn.sessionToken,
        reAuthenticatedAt: now,
        metadata: null,
        now: addSeconds(now, 2),
      } as unknown as Parameters<typeof service.closeCurrentAccountByToken>[0]),
    ).rejects.toMatchObject({
      code: UniAuthErrorCode.InvalidInput,
    })
    await expect(
      service.setCurrentAccountPasswordByToken({
        sessionToken: signedIn.sessionToken,
        password: 'first-password',
        reAuthenticatedAt: now,
        metadata: 'not-a-record',
        now: addSeconds(now, 3),
      } as unknown as Parameters<typeof service.setCurrentAccountPasswordByToken>[0]),
    ).rejects.toMatchObject({
      code: UniAuthErrorCode.InvalidInput,
    })
    await expect(
      service.startCurrentAccountContactChange({
        sessionToken: signedIn.sessionToken,
        channel: OtpChannel.Email,
        target: 'current-account-request-metadata-new@example.com',
        reAuthenticatedAt: now,
        metadata: ['not-a-record'],
        now: addSeconds(now, 4),
      } as unknown as Parameters<typeof service.startCurrentAccountContactChange>[0]),
    ).rejects.toMatchObject({
      code: UniAuthErrorCode.InvalidInput,
    })

    const nullPrototypeMetadata = Object.assign(Object.create(null) as Record<string, unknown>, {
      source: 'settings',
    })

    await service.updateCurrentAccountProfileByToken({
      sessionToken: signedIn.sessionToken,
      displayName: 'Alice',
      reAuthenticatedAt: now,
      metadata: nullPrototypeMetadata,
      now: addSeconds(now, 5),
    })

    expect(store.listAuditEvents()).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          type: AuditEventType.AccountProfileUpdated,
          metadata: {
            changedFields: ['displayName'],
            requestMetadata: { source: 'settings' },
          },
        }),
      ]),
    )
  })

  it('keeps stale disabled-user current-account action helpers neutral', async () => {
    const { service, store } = createInMemoryAuthKit()
    const signedIn = await service.signIn({
      assertion: assertion({
        providerUserId: 'current-account-actions-disabled',
        email: 'current-account-actions-disabled@example.com',
        emailVerified: true,
      }),
      now,
    })
    const secondSession = await service.createSession({
      userId: signedIn.user.id,
      now: addSeconds(now, 5),
    })

    await store.userRepo.update(signedIn.user.id, {
      disabledAt: addSeconds(now, 10),
    })

    await expect(
      service.revokeOwnedSessionByToken({
        sessionToken: signedIn.sessionToken,
        targetSessionId: secondSession.session.id,
        now: addSeconds(now, 20),
      }),
    ).rejects.toMatchObject({
      code: UniAuthErrorCode.SessionNotFound,
    })
    await expect(
      service.unlinkCurrentIdentityByToken({
        sessionToken: signedIn.sessionToken,
        identityId: signedIn.identity.id,
        reAuthenticatedAt: addSeconds(now, 20),
        now: addSeconds(now, 20),
      }),
    ).rejects.toMatchObject({
      code: UniAuthErrorCode.SessionNotFound,
    })
    await expect(
      service.setCurrentAccountPasswordByToken({
        sessionToken: signedIn.sessionToken,
        password: 'password',
        reAuthenticatedAt: addSeconds(now, 20),
        now: addSeconds(now, 20),
      }),
    ).rejects.toMatchObject({
      code: UniAuthErrorCode.SessionNotFound,
    })
    await expect(
      service.changeCurrentAccountPasswordByToken({
        sessionToken: signedIn.sessionToken,
        currentPassword: 'password',
        newPassword: 'new-password',
        reAuthenticatedAt: addSeconds(now, 20),
        now: addSeconds(now, 20),
      }),
    ).rejects.toMatchObject({
      code: UniAuthErrorCode.SessionNotFound,
    })
    await expect(
      service.closeCurrentAccountByToken({
        sessionToken: signedIn.sessionToken,
        reAuthenticatedAt: addSeconds(now, 20),
        now: addSeconds(now, 20),
      }),
    ).rejects.toMatchObject({
      code: UniAuthErrorCode.SessionNotFound,
    })
    await expect(
      service.updateCurrentAccountProfileByToken({
        sessionToken: signedIn.sessionToken,
        displayName: 'Updated',
        now: addSeconds(now, 20),
      }),
    ).rejects.toMatchObject({
      code: UniAuthErrorCode.SessionNotFound,
    })
  })
})
