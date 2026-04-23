import { describe, expect, it } from 'vitest'
import {
  AuthIdentityStatus,
  DefaultAuthService,
  SessionStatus,
  UniAuthErrorCode,
  addSeconds,
  asIdentityId,
  asSessionId,
  asUserId,
  createDefaultAuthPolicy,
} from '../src'
import { InMemoryAuthStore, InMemoryPasswordHasher, createInMemoryAuthKit } from '../src/testing'
import { assertion, now } from './helpers.js'

describe('DefaultAuthService edge cases', () => {
  it('covers uncommon sign-in, session, link, unlink, and merge branches', async () => {
    const defaultStore = new InMemoryAuthStore()
    const defaultService = new DefaultAuthService({ repos: defaultStore })
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

    await defaultService.signIn({
      assertion: assertion({
        provider: 'email',
        providerUserId: 'alice',
      }),
      metadata: { mode: 'exact' },
      sessionExpiresAt: addSeconds(now, 30),
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
    })

    const explicitSession = await defaultService.createSession({
      userId: first.user.id,
      expiresAt: addSeconds(now, 5),
      metadata: { manual: true },
      now,
    })

    expect(explicitSession.metadata).toEqual({ manual: true })
    expect(await defaultService.getUserIdentities(first.user.id)).toHaveLength(1)
    await defaultService.revokeSession(explicitSession.id)
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
          now,
        })
        .catch((caught: unknown) => caught),
    ).toMatchObject({ code: UniAuthErrorCode.InvalidInput })

    await defaultStore.userRepo.update(second.user.id, { disabledAt: now })
    expect(
      await defaultService.getUserIdentities(second.user.id).catch((caught: unknown) => caught),
    ).toMatchObject({
      code: UniAuthErrorCode.UserNotFound,
    })
    expect(
      await defaultService
        .mergeAccounts({
          sourceUserId: asUserId('missing-source'),
          targetUserId: first.user.id,
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
    await malformedKit.store.identityRepo.create({
      id: asIdentityId('missing-user-identity'),
      userId: asUserId('missing-user'),
      provider: 'email',
      providerUserId: 'missing-user',
      email: 'missing-user@example.com',
      emailVerified: true,
      status: AuthIdentityStatus.Active,
      createdAt: now,
      updatedAt: now,
    })

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

  it('covers merge behavior for already revoked source sessions', async () => {
    const mergeKit = createInMemoryAuthKit({
      policy: createDefaultAuthPolicy({ allowMergeAccounts: true, requireReAuthFor: [] }),
      clock: { now: () => now },
    })
    const source = await mergeKit.service.signIn({
      assertion: assertion({ provider: 'email', providerUserId: 'source' }),
      now,
    })
    const target = await mergeKit.service.signIn({
      assertion: assertion({ provider: 'email', providerUserId: 'target' }),
      now,
    })
    const nonActiveSourceSession = await mergeKit.service.createSession({
      userId: source.user.id,
      now,
    })

    await mergeKit.service.revokeSession(nonActiveSourceSession.id)
    expect(
      await mergeKit.service.mergeAccounts({
        sourceUserId: source.user.id,
        targetUserId: target.user.id,
      }),
    ).toMatchObject({ movedIdentityIds: [source.identity.id] })
    expect(nonActiveSourceSession.status).toBe(SessionStatus.Active)
  })

  it('rolls merge state back when audit persistence fails inside the transaction boundary', async () => {
    const policy = createDefaultAuthPolicy({ allowMergeAccounts: true, requireReAuthFor: [] })
    const store = new InMemoryAuthStore()
    const setupService = new DefaultAuthService({
      repos: store,
      transaction: store,
      policy,
      passwordHasher: new InMemoryPasswordHasher(),
    })
    const source = await setupService.signIn({
      assertion: assertion({
        provider: 'email',
        providerUserId: 'source-rollback',
        email: 'source-rollback@example.com',
        emailVerified: true,
      }),
      now,
    })
    const target = await setupService.signIn({
      assertion: assertion({
        provider: 'email',
        providerUserId: 'target-rollback',
        email: 'target-rollback@example.com',
        emailVerified: true,
      }),
      now,
    })
    const sourceCredential = await setupService.setPassword({
      userId: source.user.id,
      email: 'source-rollback@example.com',
      password: 'rollback-secret',
      now,
    })
    const auditCountBeforeMerge = store.listAuditEvents().length
    const auditFailure = new Error('audit persistence failed')
    const failingService = new DefaultAuthService({
      repos: {
        userRepo: store.userRepo,
        identityRepo: store.identityRepo,
        credentialRepo: store.credentialRepo,
        verificationRepo: store.verificationRepo,
        sessionRepo: store.sessionRepo,
        auditLogRepo: {
          append: async () => {
            throw auditFailure
          },
        },
      },
      transaction: store,
      policy,
    })

    await expect(
      failingService.mergeAccounts({
        sourceUserId: source.user.id,
        targetUserId: target.user.id,
        reAuthenticatedAt: now,
        now,
      }),
    ).rejects.toBe(auditFailure)

    expect(store.listUsers().find((user) => user.id === source.user.id)?.disabledAt).toBeUndefined()
    expect(
      store
        .listIdentities()
        .filter((identity) => identity.userId === source.user.id)
        .map((identity) => identity.id),
    ).toContain(source.identity.id)
    expect(
      store
        .listCredentials()
        .filter((credential) => credential.id === sourceCredential.id)
        .map((credential) => credential.userId),
    ).toEqual([source.user.id])
    expect(
      store
        .listSessions()
        .filter((session) => session.userId === source.user.id)
        .map((session) => session.status),
    ).toEqual([SessionStatus.Active])
    expect(store.listAuditEvents()).toHaveLength(auditCountBeforeMerge)
  })

  it('rejects merge for a disabled source that still has active state attached', async () => {
    const policy = createDefaultAuthPolicy({ allowMergeAccounts: true, requireReAuthFor: [] })
    const store = new InMemoryAuthStore()
    const service = new DefaultAuthService({
      repos: store,
      transaction: store,
      policy,
    })
    const target = await service.signIn({
      assertion: assertion({
        provider: 'email',
        providerUserId: 'merge-target',
        email: 'merge-target@example.com',
        emailVerified: true,
      }),
      now,
    })

    await store.userRepo.create({
      id: asUserId('disabled-source'),
      createdAt: now,
      updatedAt: now,
      disabledAt: now,
    })
    await store.identityRepo.create({
      id: asIdentityId('disabled-source-identity'),
      userId: asUserId('disabled-source'),
      provider: 'email',
      providerUserId: 'disabled-source@example.com',
      email: 'disabled-source@example.com',
      emailVerified: true,
      status: AuthIdentityStatus.Active,
      createdAt: now,
      updatedAt: now,
    })

    await expect(
      service.mergeAccounts({
        sourceUserId: asUserId('disabled-source'),
        targetUserId: target.user.id,
        reAuthenticatedAt: now,
        now,
      }),
    ).rejects.toMatchObject({
      code: UniAuthErrorCode.UserNotFound,
    })
  })
})
