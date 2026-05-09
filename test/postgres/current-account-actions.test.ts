import { describe, expect, it } from 'vitest'
import {
  AuditEventType,
  AuthPolicyAction,
  OtpChannel,
  SessionStatus,
  UniAuthErrorCode,
  VerificationPurpose,
  addSeconds,
  createDefaultAuthPolicy,
} from '../../src'
import { createPostgresTestKit, now } from './support.js'

describe('Postgres current-account action helpers', () => {
  it('revokes one owned Postgres session by trusted session token while preserving the current session', async () => {
    const { service } = await createPostgresTestKit()
    const signedIn = await service.signIn({
      assertion: {
        provider: 'email',
        providerUserId: 'pg-current-account-owned-session',
        email: 'pg-current-account-owned-session@example.com',
        emailVerified: true,
      },
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

  it('unlinks and changes current-account credentials through the Postgres token-based helpers', async () => {
    const { service } = await createPostgresTestKit({
      policy: createDefaultAuthPolicy({
        requireReAuthFor: [
          AuthPolicyAction.Unlink,
          AuthPolicyAction.SetPassword,
          AuthPolicyAction.ChangePassword,
        ],
      }),
    })
    const signedIn = await service.signIn({
      assertion: {
        provider: 'email',
        providerUserId: 'pg-current-account-actions',
        email: 'pg-current-account-actions@example.com',
        emailVerified: true,
      },
      now,
    })
    const linked = await service.link({
      userId: signedIn.user.id,
      assertion: {
        provider: 'github',
        providerUserId: 'pg-current-account-actions-github',
        email: 'pg-current-account-actions@example.com',
        emailVerified: true,
      },
      now: addSeconds(now, 5),
    })

    await service.setCurrentAccountPasswordByToken({
      sessionToken: signedIn.sessionToken,
      password: 'first-password',
      reAuthenticatedAt: addSeconds(now, 10),
      now: addSeconds(now, 10),
    })
    await service.changeCurrentAccountPasswordByToken({
      sessionToken: signedIn.sessionToken,
      currentPassword: 'first-password',
      newPassword: 'second-password',
      reAuthenticatedAt: addSeconds(now, 11),
      now: addSeconds(now, 11),
    })
    await service.unlinkCurrentIdentityByToken({
      sessionToken: signedIn.sessionToken,
      identityId: linked.identity.id,
      reAuthenticatedAt: addSeconds(now, 12),
      now: addSeconds(now, 12),
    })

    await expect(
      service.signInWithPassword({
        email: 'pg-current-account-actions@example.com',
        password: 'first-password',
        now: addSeconds(now, 13),
      }),
    ).rejects.toMatchObject({
      code: UniAuthErrorCode.InvalidCredentials,
    })
    await expect(
      service.signInWithPassword({
        email: 'pg-current-account-actions@example.com',
        password: 'second-password',
        now: addSeconds(now, 13),
      }),
    ).resolves.toMatchObject({
      user: { id: signedIn.user.id },
    })
    expect(await service.getUserIdentities(signedIn.user.id)).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          id: signedIn.identity.id,
        }),
        expect.objectContaining({
          provider: 'password',
        }),
      ]),
    )
  })

  it('updates the current Postgres account profile by trusted session token', async () => {
    const { service } = await createPostgresTestKit({
      policy: createDefaultAuthPolicy({
        requireReAuthFor: [AuthPolicyAction.UpdateProfile],
      }),
    })
    const signedIn = await service.signIn({
      assertion: {
        provider: 'email',
        providerUserId: 'pg-current-account-profile',
        email: 'pg-current-account-profile@example.com',
        emailVerified: true,
        phone: '+15550000002',
        phoneVerified: true,
        displayName: 'Before',
        metadata: { externalProfileId: 'pg-profile-1' },
      },
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
      email: 'pg-current-account-profile@example.com',
      phone: '+15550000002',
      updatedAt,
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

  it('normalizes blank Postgres profile display names and rejects empty updates', async () => {
    const { service } = await createPostgresTestKit({
      clock: { now: () => now },
    })
    const signedIn = await service.signIn({
      assertion: {
        provider: 'email',
        providerUserId: 'pg-current-account-profile-blank',
        email: 'pg-current-account-profile-blank@example.com',
        emailVerified: true,
        displayName: 'Before',
      },
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
    await expect(
      service.updateCurrentAccountProfileByToken({
        sessionToken: signedIn.sessionToken,
      }),
    ).rejects.toMatchObject({
      code: UniAuthErrorCode.InvalidInput,
    })
  })

  it('finishes Postgres current-account phone changes by trusted session token', async () => {
    const { service, smsSender } = await createPostgresTestKit({
      policy: createDefaultAuthPolicy({
        requireReAuthFor: [AuthPolicyAction.UpdateContact],
      }),
    })
    const signedIn = await service.signIn({
      assertion: {
        provider: 'email',
        providerUserId: 'pg-current-account-contact-change',
        email: 'pg-current-account-contact-change@example.com',
        emailVerified: true,
      },
      now,
    })
    const originalIdentities = await service.getUserIdentities(signedIn.user.id)

    await expect(
      service.startCurrentAccountContactChange({
        sessionToken: signedIn.sessionToken,
        channel: OtpChannel.Phone,
        target: '+1 (555) 000-0005',
        secret: '444444',
        now: addSeconds(now, 10),
      }),
    ).rejects.toMatchObject({
      code: UniAuthErrorCode.ReAuthRequired,
    })

    const started = await service.startCurrentAccountContactChange({
      sessionToken: signedIn.sessionToken,
      channel: OtpChannel.Phone,
      target: '+1 (555) 000-0005',
      secret: '444444',
      reAuthenticatedAt: addSeconds(now, 20),
      now: addSeconds(now, 20),
      metadata: { source: 'settings' },
    })

    expect(smsSender.listMessages()).toEqual([
      expect.objectContaining({
        to: '+15550000005',
        metadata: expect.objectContaining({
          purpose: VerificationPurpose.ContactChange,
          delivery: OtpChannel.Phone,
        }),
      }),
    ])

    const updated = await service.finishCurrentAccountContactChange({
      sessionToken: signedIn.sessionToken,
      verificationId: started.verificationId,
      secret: '444444',
      now: addSeconds(now, 30),
      metadata: { source: 'settings-finish' },
    })

    expect(updated).toMatchObject({
      id: signedIn.user.id,
      email: 'pg-current-account-contact-change@example.com',
      phone: '+15550000005',
      updatedAt: addSeconds(now, 30),
    })
    expect(await service.getUserIdentities(signedIn.user.id)).toEqual(originalIdentities)
    await expect(service.getAuditEvents({ userId: signedIn.user.id })).resolves.toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          type: AuditEventType.AccountContactUpdated,
          sessionId: signedIn.session.id,
          metadata: {
            verificationId: started.verificationId,
            channel: OtpChannel.Phone,
            changedFields: ['phone'],
            requestMetadata: { source: 'settings-finish' },
          },
        }),
      ]),
    )
  })

  it('keeps expired and revoked Postgres current-account profile update contexts neutral', async () => {
    const { service } = await createPostgresTestKit()
    const revoked = await service.signIn({
      assertion: {
        provider: 'email',
        providerUserId: 'pg-current-account-profile-revoked',
        email: 'pg-current-account-profile-revoked@example.com',
        emailVerified: true,
      },
      now,
    })
    const expired = await service.signIn({
      assertion: {
        provider: 'email',
        providerUserId: 'pg-current-account-profile-expired',
        email: 'pg-current-account-profile-expired@example.com',
        emailVerified: true,
      },
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

  it('closes the current Postgres account by trusted session token and revokes sessions', async () => {
    const { service, store } = await createPostgresTestKit({
      policy: createDefaultAuthPolicy({
        requireReAuthFor: [AuthPolicyAction.CloseAccount],
      }),
    })
    const signedIn = await service.signIn({
      assertion: {
        provider: 'email',
        providerUserId: 'pg-current-account-close',
        email: 'pg-current-account-close@example.com',
        emailVerified: true,
      },
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
    await expect(store.sessionRepo.findById(signedIn.session.id)).resolves.toMatchObject({
      status: SessionStatus.Revoked,
      revokedAt: closedAt,
    })
    await expect(store.sessionRepo.findById(secondSession.session.id)).resolves.toMatchObject({
      status: SessionStatus.Revoked,
      revokedAt: closedAt,
    })
    await expect(service.getAuditEvents({ userId: signedIn.user.id })).resolves.toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          type: AuditEventType.AccountClosed,
          sessionId: signedIn.session.id,
          metadata: {
            revokedSessionIds: [signedIn.session.id, secondSession.session.id],
            requestMetadata: { source: 'settings' },
          },
        }),
      ]),
    )
  })

  it('keeps stale disabled-user Postgres current-account action helpers neutral', async () => {
    const { service, store } = await createPostgresTestKit()
    const signedIn = await service.signIn({
      assertion: {
        provider: 'email',
        providerUserId: 'pg-current-account-actions-disabled',
        email: 'pg-current-account-actions-disabled@example.com',
        emailVerified: true,
      },
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
