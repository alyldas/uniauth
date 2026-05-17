import { describe, expect, it } from 'vitest'
import {
  AuthIdentityStatus,
  DefaultAuthService,
  UniAuthErrorCode,
  addSeconds,
  asIdentityId,
  asSessionId,
  asUserId,
  asVerificationId,
  createDefaultAuthPolicy,
  type AuthIdentity,
  type IdentityId,
} from '../../src'
import { InMemoryAuthStore, InMemoryPasswordHasher, createInMemoryAuthKit } from '../../src/testing'
import { assertion, now } from '../helpers.js'

describe('DefaultAuthService sign-in and session edge cases', () => {
  it('rethrows unexpected user lookup failures from session-context resolution', async () => {
    const store = new InMemoryAuthStore()
    const setupService = new DefaultAuthService({ repos: store })
    const result = await setupService.signIn({
      assertion: assertion({
        provider: 'email',
        providerUserId: 'session-context-user-lookup-failure',
      }),
      now,
    })
    const lookupFailure = new Error('user lookup failed')
    const service = new DefaultAuthService({
      repos: {
        userRepo: {
          ...store.userRepo,
          findById: async () => {
            throw lookupFailure
          },
        },
        identityRepo: store.identityRepo,
        credentialRepo: store.credentialRepo,
        verificationRepo: store.verificationRepo,
        sessionRepo: store.sessionRepo,
        auditLogRepo: store.auditLogRepo,
      },
    })

    await expect(
      service.resolveSessionContext({
        sessionToken: result.sessionToken,
        now,
      }),
    ).rejects.toBe(lookupFailure)
  })

  it('covers uncommon sign-in, session, link, unlink, and read-side branches', async () => {
    const defaultStore = new InMemoryAuthStore()
    const defaultService = new DefaultAuthService({
      repos: defaultStore,
      passwordHasher: new InMemoryPasswordHasher(),
    })
    const first = await defaultService.signIn({
      assertion: assertion({
        provider: '  email  ',
        providerUserId: ' alice ',
        email: ' Alice@Example.com ',
        emailVerified: true,
        phone: ' +1 (555) 123-4567 ',
        phoneVerified: true,
        displayName: ' Alice ',
        metadata: { source: 'test' },
      }),
    })

    expect(first.user.id).toMatch(/^usr_/)
    expect(first.user.email).toBe('alice@example.com')
    expect(first.user.phone).toBe('+15551234567')
    expect(first.identity.metadata).toEqual({ source: 'test' })

    const blankProfile = await defaultService.signIn({
      assertion: {
        provider: 'email',
        providerUserId: 'blank-profile',
        email: '   ',
        emailVerified: true,
        phone: ' - ',
        phoneVerified: true,
        displayName: '   ',
      },
      now,
    })

    expect(blankProfile.user.email).toBeUndefined()
    expect(blankProfile.user.phone).toBeUndefined()
    expect(blankProfile.user.displayName).toBeUndefined()
    expect(blankProfile.identity.email).toBeUndefined()
    expect(blankProfile.identity.phone).toBeUndefined()

    const exact = await defaultService.signIn({
      assertion: assertion({
        provider: 'email',
        providerUserId: 'alice',
      }),
      metadata: { mode: 'exact' },
      sessionExpiresAt: addSeconds(now, 30),
      now,
    })
    await defaultService.signIn({
      assertion: assertion({
        provider: 'email',
        providerUserId: 'charlie',
        email: 'charlie@example.com',
        emailVerified: true,
      }),
      metadata: { mode: 'new-user-options' },
      sessionExpiresAt: addSeconds(now, 30),
      now,
    })

    const explicitSession = await defaultService.createSession({
      userId: first.user.id,
      expiresAt: addSeconds(now, 5),
      metadata: { manual: true },
      now,
    })

    expect(explicitSession.session.metadata).toEqual({ manual: true })
    expect(await defaultService.getUser(first.user.id)).toMatchObject({
      id: first.user.id,
      email: 'alice@example.com',
    })
    expect(await defaultService.getUserIdentities(first.user.id)).toHaveLength(1)
    expect(
      (await defaultService.getUserSessions(first.user.id)).map((session) => session.id),
    ).toEqual([first.session.id, exact.session.id, explicitSession.session.id])
    expect(
      await defaultService.resolveSession({ sessionToken: explicitSession.sessionToken, now }),
    ).toBe(explicitSession.session)
    await expect(
      defaultService.createSession({
        userId: first.user.id,
        metadata: ['not-a-record'],
        now,
      } as unknown as Parameters<typeof defaultService.createSession>[0]),
    ).rejects.toMatchObject({
      code: UniAuthErrorCode.InvalidInput,
    })
    const nullPrototypeSessionMetadata = Object.assign(
      Object.create(null) as Record<string, unknown>,
      { mode: 'manual' },
    )
    await expect(
      defaultService.createSession({
        userId: first.user.id,
        metadata: nullPrototypeSessionMetadata,
        now,
      }),
    ).resolves.toMatchObject({
      session: {
        metadata: { mode: 'manual' },
      },
    })
    expect(
      await defaultService.touchSession({
        sessionId: explicitSession.session.id,
        now: addSeconds(now, 1),
      }),
    ).toMatchObject({
      id: explicitSession.session.id,
      lastSeenAt: addSeconds(now, 1),
    })
    await defaultService.revokeSession(explicitSession.session.id)
    await expect(
      defaultService.resolveSession({ sessionToken: explicitSession.sessionToken, now }),
    ).rejects.toMatchObject({
      code: UniAuthErrorCode.SessionNotFound,
    })
    await expect(
      defaultService.touchSession({
        sessionId: explicitSession.session.id,
        now: addSeconds(now, 2),
      }),
    ).rejects.toMatchObject({
      code: UniAuthErrorCode.SessionNotFound,
    })
    expect(
      await defaultService.revokeSession(asSessionId('missing')).catch((caught: unknown) => caught),
    ).toMatchObject({
      code: UniAuthErrorCode.SessionNotFound,
    })

    expect(
      await defaultService
        .link({
          userId: first.user.id,
          assertion: assertion({
            provider: 'email',
            providerUserId: 'alice',
          }),
          now,
        })
        .then((result) => result.linked),
    ).toBe(false)
    await expect(
      defaultService.link({
        userId: first.user.id,
        assertion: assertion({
          provider: 'invalid-metadata-link',
          providerUserId: 'invalid-metadata-link',
        }),
        metadata: ['not-a-record'],
        now,
      } as unknown as Parameters<typeof defaultService.link>[0]),
    ).rejects.toMatchObject({
      code: UniAuthErrorCode.InvalidInput,
    })

    const linked = await defaultService.link({
      userId: first.user.id,
      assertion: assertion({
        provider: 'oauth',
        providerUserId: 'alice-oauth',
        email: 'alice@example.com',
        metadata: { linked: true },
      }),
      metadata: { action: 'manual-link' },
      now,
    })

    expect(linked.linked).toBe(true)
    const clockLinked = await defaultService.link({
      userId: first.user.id,
      assertion: assertion({
        provider: 'clock',
        providerUserId: 'clock-link',
      }),
    })

    await defaultService.unlink({
      userId: first.user.id,
      identityId: clockLinked.identity.id,
    })
    await defaultService.unlink({
      userId: first.user.id,
      identityId: linked.identity.id,
      metadata: { action: 'unlink' },
      now,
    })
    await expect(
      defaultService.unlink({
        userId: first.user.id,
        identityId: first.identity.id,
        metadata: 'not-a-record',
        now,
      } as unknown as Parameters<typeof defaultService.unlink>[0]),
    ).rejects.toMatchObject({
      code: UniAuthErrorCode.InvalidInput,
    })
    expect(
      await defaultService
        .unlink({ userId: first.user.id, identityId: linked.identity.id, now })
        .catch((caught: unknown) => caught),
    ).toMatchObject({
      code: UniAuthErrorCode.IdentityNotFound,
    })

    const second = await defaultService.signIn({
      assertion: assertion({
        provider: 'email',
        providerUserId: 'bob',
        email: 'bob@example.com',
        emailVerified: true,
      }),
      now,
    })

    expect(
      await defaultService
        .unlink({ userId: second.user.id, identityId: first.identity.id, now })
        .catch((caught: unknown) => caught),
    ).toMatchObject({
      code: UniAuthErrorCode.IdentityNotFound,
    })
    expect(
      await defaultService
        .mergeAccounts({
          sourceUserId: second.user.id,
          targetUserId: second.user.id,
          sourceSessionToken: second.sessionToken,
          now,
        })
        .catch((caught: unknown) => caught),
    ).toMatchObject({ code: UniAuthErrorCode.InvalidInput })
    await expect(
      defaultService.mergeAccounts({
        sourceUserId: second.user.id,
        targetUserId: first.user.id,
        sourceSessionToken: second.sessionToken,
        metadata: ['not-a-record'],
        now,
      } as unknown as Parameters<typeof defaultService.mergeAccounts>[0]),
    ).rejects.toMatchObject({
      code: UniAuthErrorCode.InvalidInput,
    })
    await expect(
      defaultService.setPassword({
        userId: first.user.id,
        email: 'alice@example.com',
        password: 'first-password',
        metadata: ['not-a-record'],
        now,
      } as unknown as Parameters<typeof defaultService.setPassword>[0]),
    ).rejects.toMatchObject({
      code: UniAuthErrorCode.InvalidInput,
    })
    await defaultService.setPassword({
      userId: first.user.id,
      email: 'alice@example.com',
      password: 'first-password',
      metadata: { mode: 'set' },
      now,
    })
    await expect(
      defaultService.changePassword({
        userId: first.user.id,
        currentPassword: 'first-password',
        newPassword: 'second-password',
        metadata: null,
        now,
      } as unknown as Parameters<typeof defaultService.changePassword>[0]),
    ).rejects.toMatchObject({
      code: UniAuthErrorCode.InvalidInput,
    })

    await defaultStore.userRepo.update(second.user.id, { disabledAt: now })
    expect(
      await defaultService.getUser(second.user.id).catch((caught: unknown) => caught),
    ).toMatchObject({
      code: UniAuthErrorCode.UserNotFound,
    })
    expect(
      await defaultService.getUserIdentities(second.user.id).catch((caught: unknown) => caught),
    ).toMatchObject({
      code: UniAuthErrorCode.UserNotFound,
    })
    expect(
      await defaultService.getUserSessions(second.user.id).catch((caught: unknown) => caught),
    ).toMatchObject({
      code: UniAuthErrorCode.UserNotFound,
    })
    expect(
      await defaultService.getUserCredentials(second.user.id).catch((caught: unknown) => caught),
    ).toMatchObject({
      code: UniAuthErrorCode.UserNotFound,
    })
    expect(
      await defaultService
        .getAccountSecuritySnapshot(second.user.id)
        .catch((caught: unknown) => caught),
    ).toMatchObject({
      code: UniAuthErrorCode.UserNotFound,
    })
    expect(
      await defaultService
        .getVerification(asVerificationId('missing-verification'))
        .catch((caught: unknown) => caught),
    ).toMatchObject({
      code: UniAuthErrorCode.VerificationNotFound,
    })
    expect(
      await defaultService
        .revokeUserSessions({
          userId: first.user.id,
          exceptSessionId: asSessionId('missing-session'),
          now,
        })
        .catch((caught: unknown) => caught),
    ).toMatchObject({
      code: UniAuthErrorCode.SessionNotFound,
    })
    expect(
      await defaultService
        .mergeAccounts({
          sourceUserId: asUserId('missing-source'),
          targetUserId: first.user.id,
          sourceSessionToken: first.sessionToken,
          reAuthenticatedAt: now,
          now,
        })
        .catch((caught: unknown) => caught),
    ).toMatchObject({
      code: UniAuthErrorCode.UserNotFound,
    })
  })

  it('covers disabled and malformed auto-link candidates', async () => {
    const malformedKit = createInMemoryAuthKit({
      policy: createDefaultAuthPolicy({ allowAutoLink: true }),
    })
    await malformedKit.store.userRepo.create({
      id: asUserId('disabled-user'),
      createdAt: now,
      updatedAt: now,
    })
    await malformedKit.store.userRepo.update(asUserId('disabled-user'), { disabledAt: now })
    await malformedKit.store.identityRepo.create({
      id: asIdentityId('disabled-target-identity'),
      userId: asUserId('disabled-user'),
      provider: 'email',
      providerUserId: 'disabled-target',
      email: 'disabled@example.com',
      emailVerified: true,
      status: AuthIdentityStatus.Active,
      createdAt: now,
      updatedAt: now,
    })
    await malformedKit.store.identityRepo.create({
      id: asIdentityId('disabled-email-identity'),
      userId: asUserId('disabled-user'),
      provider: 'email',
      providerUserId: 'disabled-email',
      email: 'inactive@example.com',
      emailVerified: true,
      disabledAt: now,
      status: AuthIdentityStatus.Active,
      createdAt: now,
      updatedAt: now,
    })
    await malformedKit.store.identityRepo.create({
      id: asIdentityId('disabled-phone-identity'),
      userId: asUserId('disabled-user'),
      provider: 'phone',
      providerUserId: 'disabled-phone',
      phone: '+15559990000',
      phoneVerified: true,
      disabledAt: now,
      status: AuthIdentityStatus.Active,
      createdAt: now,
      updatedAt: now,
    })
    const orphanedIdentity: AuthIdentity = {
      id: asIdentityId('missing-user-identity'),
      userId: asUserId('missing-user'),
      provider: 'email',
      providerUserId: 'missing-user',
      email: 'missing-user@example.com',
      emailVerified: true,
      status: AuthIdentityStatus.Active,
      createdAt: now,
      updatedAt: now,
    }
    const malformedStoreInternals = malformedKit.store as unknown as {
      readonly identities: Map<AuthIdentity['id'], AuthIdentity>
      readonly identityKeys: Map<string, IdentityId>
    }
    malformedStoreInternals.identities.set(orphanedIdentity.id, orphanedIdentity)
    malformedStoreInternals.identityKeys.set(
      JSON.stringify([orphanedIdentity.provider, orphanedIdentity.providerUserId]),
      orphanedIdentity.id,
    )

    const inactiveEmailTarget = await malformedKit.service.signIn({
      assertion: assertion({
        provider: 'oauth',
        providerUserId: 'inactive-email-oauth',
        email: 'inactive@example.com',
        emailVerified: true,
      }),
      now,
    })
    const inactivePhoneTarget = await malformedKit.service.signIn({
      assertion: assertion({
        provider: 'oauth',
        providerUserId: 'inactive-phone-oauth',
        phone: '+15559990000',
        phoneVerified: true,
      }),
      now,
    })
    const disabledTarget = await malformedKit.service.signIn({
      assertion: assertion({
        provider: 'oauth',
        providerUserId: 'disabled-oauth',
        email: 'disabled@example.com',
        emailVerified: true,
      }),
      now,
    })
    const missingUserTarget = await malformedKit.service.signIn({
      assertion: assertion({
        provider: 'oauth',
        providerUserId: 'missing-user-oauth',
        email: 'missing-user@example.com',
        emailVerified: true,
      }),
      now,
    })

    expect(inactiveEmailTarget.isNewUser).toBe(true)
    expect(inactivePhoneTarget.isNewUser).toBe(true)
    expect(disabledTarget.isNewUser).toBe(true)
    expect(missingUserTarget.isNewUser).toBe(true)
  })
})
