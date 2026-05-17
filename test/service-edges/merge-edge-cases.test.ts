import { describe, expect, it } from 'vitest'
import {
  AuthIdentityStatus,
  DefaultAuthService,
  SessionStatus,
  UniAuthErrorCode,
  asIdentityId,
  asUserId,
  createDefaultAuthPolicy,
} from '../../src'
import { InMemoryAuthStore, InMemoryPasswordHasher, createInMemoryAuthKit } from '../../src/testing'
import { assertion, now } from '../helpers.js'

describe('DefaultAuthService merge edge cases', () => {
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

    await mergeKit.service.revokeSession(nonActiveSourceSession.session.id)
    expect(
      await mergeKit.service.mergeAccounts({
        sourceUserId: source.user.id,
        targetUserId: target.user.id,
        sourceSessionToken: source.sessionToken,
      }),
    ).toMatchObject({ movedIdentityIds: [source.identity.id] })
    expect(nonActiveSourceSession.session.status).toBe(SessionStatus.Active)
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
          list: async () => [],
        },
      },
      transaction: store,
      policy,
    })

    await expect(
      failingService.mergeAccounts({
        sourceUserId: source.user.id,
        targetUserId: target.user.id,
        sourceSessionToken: source.sessionToken,
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
        sourceSessionToken: target.sessionToken,
        reAuthenticatedAt: now,
        now,
      }),
    ).rejects.toMatchObject({
      code: UniAuthErrorCode.UserNotFound,
    })
  })
})
