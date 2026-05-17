import { describe, expect, it } from 'vitest'
import {
  AuditEventType,
  SessionStatus,
  UniAuthErrorCode,
  addSeconds,
  createDefaultAuthPolicy,
  isUniAuthError,
} from '../../src'
import { StaticAuthProvider, createInMemoryAuthKit } from '../../src/testing'
import { assertion, now } from './support.js'

describe('DefaultAuthService policies and merge flows', () => {
  it('uses exact provider identity match before any profile matching', async () => {
    const { service, store } = createInMemoryAuthKit()

    const first = await service.signIn({ assertion: assertion(), now })
    const second = await service.signIn({
      assertion: assertion({ email: 'different@example.com' }),
      now,
    })

    expect(second.isNewUser).toBe(false)
    expect(second.isNewIdentity).toBe(false)
    expect(second.user.id).toBe(first.user.id)
    expect(store.listUsers()).toHaveLength(1)
    expect(store.listIdentities()).toHaveLength(1)
    expect(store.listSessions()).toHaveLength(2)
  })

  it('does not silently merge users by verified email under the default policy', async () => {
    const { service, store } = createInMemoryAuthKit()

    const emailUser = await service.signIn({ assertion: assertion(), now })
    const oauthUser = await service.signIn({
      assertion: assertion({ provider: 'oauth', providerUserId: 'oauth-alice' }),
      now,
    })

    expect(oauthUser.isNewUser).toBe(true)
    expect(oauthUser.user.id).not.toBe(emailUser.user.id)
    expect(store.listUsers()).toHaveLength(2)
    expect(store.listIdentities()).toHaveLength(2)
  })

  it('auto-links only when the policy explicitly allows it', async () => {
    const { service, store } = createInMemoryAuthKit({
      policy: createDefaultAuthPolicy({ allowAutoLink: true }),
    })

    const emailUser = await service.signIn({ assertion: assertion(), now })
    const oauthUser = await service.signIn({
      assertion: assertion({ provider: 'oauth', providerUserId: 'oauth-alice' }),
      now,
    })

    expect(oauthUser.isNewUser).toBe(false)
    expect(oauthUser.isNewIdentity).toBe(true)
    expect(oauthUser.user.id).toBe(emailUser.user.id)
    expect(store.listUsers()).toHaveLength(1)
    expect(store.listIdentities()).toHaveLength(2)
  })

  it('rejects unlinking the last active identity', async () => {
    const { service } = createInMemoryAuthKit()
    const result = await service.signIn({ assertion: assertion(), now })

    const error = await service
      .unlink({ userId: result.user.id, identityId: result.identity.id, now })
      .catch((caught: unknown) => caught)

    expect(error).toMatchObject({ code: UniAuthErrorCode.LastIdentity })
  })

  it('keeps one active identity after concurrent unlink attempts', async () => {
    const { service, store } = createInMemoryAuthKit({
      policy: createDefaultAuthPolicy({ requireReAuthFor: [] }),
    })
    const result = await service.signIn({ assertion: assertion(), now })
    const linked = await service.link({
      userId: result.user.id,
      assertion: assertion({ provider: 'oauth', providerUserId: 'concurrent-unlink' }),
      now,
    })

    const outcomes = await Promise.allSettled([
      service.unlink({ userId: result.user.id, identityId: result.identity.id, now }),
      service.unlink({ userId: result.user.id, identityId: linked.identity.id, now }),
    ])

    expect(outcomes.filter((outcome) => outcome.status === 'fulfilled')).toHaveLength(1)
    expect(outcomes.filter((outcome) => outcome.status === 'rejected')).toHaveLength(1)
    expect(
      store
        .listIdentities()
        .filter((identity) => identity.userId === result.user.id && !identity.disabledAt),
    ).toHaveLength(1)
  })

  it('rejects future re-auth markers for sensitive policy checks', async () => {
    const { service } = createInMemoryAuthKit({
      policy: createDefaultAuthPolicy({ allowMergeAccounts: true }),
    })
    const source = await service.signIn({
      assertion: assertion({ providerUserId: 'future-reauth-source' }),
      now,
    })
    const target = await service.signIn({
      assertion: assertion({ providerUserId: 'future-reauth-target' }),
      now,
    })

    await expect(
      service.mergeAccounts({
        sourceUserId: source.user.id,
        targetUserId: target.user.id,
        sourceSessionToken: source.sessionToken,
        reAuthenticatedAt: addSeconds(now, 60),
        now,
      }),
    ).rejects.toMatchObject({ code: UniAuthErrorCode.InvalidInput })
  })

  it('requires source session proof before merging active accounts', async () => {
    const { service } = createInMemoryAuthKit({
      policy: createDefaultAuthPolicy({ allowMergeAccounts: true, requireReAuthFor: [] }),
    })
    const source = await service.signIn({
      assertion: assertion({ providerUserId: 'source-proof-source' }),
      now,
    })
    const target = await service.signIn({
      assertion: assertion({ providerUserId: 'source-proof-target' }),
      now,
    })

    await expect(
      service.mergeAccounts({
        sourceUserId: source.user.id,
        targetUserId: target.user.id,
        now,
      } as unknown as Parameters<typeof service.mergeAccounts>[0]),
    ).rejects.toMatchObject({ code: UniAuthErrorCode.InvalidInput })

    await expect(
      service.mergeAccounts({
        sourceUserId: source.user.id,
        targetUserId: target.user.id,
        sourceSessionToken: target.sessionToken,
        now,
      }),
    ).rejects.toMatchObject({ code: UniAuthErrorCode.SessionNotFound })
  })

  it('rejects linking an identity already attached to another user without leaking ownership', async () => {
    const { service } = createInMemoryAuthKit()
    const first = await service.signIn({ assertion: assertion(), now })
    const second = await service.signIn({
      assertion: assertion({
        provider: 'email',
        providerUserId: 'bob',
        email: 'bob@example.com',
        displayName: 'Bob',
      }),
      now,
    })

    const error = await service
      .link({
        userId: second.user.id,
        assertion: assertion({
          provider: first.identity.provider,
          providerUserId: first.identity.providerUserId,
        }),
        now,
      })
      .catch((caught: unknown) => caught)

    expect(isUniAuthError(error)).toBe(true)

    if (!isUniAuthError(error)) {
      throw new Error('Expected a UniAuthError.')
    }

    expect(error.code).toBe(UniAuthErrorCode.IdentityAlreadyLinked)
    expect(error.message).not.toContain('another user')
    expect(error.message).not.toContain('account')
  })

  it('requires explicit merge policy and moves identities only through mergeAccounts', async () => {
    const deniedKit = createInMemoryAuthKit()
    const deniedSource = await deniedKit.service.signIn({
      assertion: assertion({ providerUserId: 'source', email: 'source@example.com' }),
      now,
    })
    const deniedTarget = await deniedKit.service.signIn({
      assertion: assertion({ providerUserId: 'target', email: 'target@example.com' }),
      now,
    })

    const deniedMergeError = await deniedKit.service
      .mergeAccounts({
        sourceUserId: deniedSource.user.id,
        targetUserId: deniedTarget.user.id,
        sourceSessionToken: deniedSource.sessionToken,
        reAuthenticatedAt: now,
        now,
      })
      .catch((caught: unknown) => caught)

    expect(deniedMergeError).toMatchObject({ code: UniAuthErrorCode.PolicyDenied })

    const allowedKit = createInMemoryAuthKit({
      policy: createDefaultAuthPolicy({ allowMergeAccounts: true, requireReAuthFor: [] }),
    })
    const source = await allowedKit.service.signIn({
      assertion: assertion({ providerUserId: 'source', email: 'source@example.com' }),
      now,
    })
    const target = await allowedKit.service.signIn({
      assertion: assertion({ providerUserId: 'target', email: 'target@example.com' }),
      now,
    })

    const merged = await allowedKit.service.mergeAccounts({
      sourceUserId: source.user.id,
      targetUserId: target.user.id,
      sourceSessionToken: source.sessionToken,
      now,
    })

    expect(merged.movedIdentityIds).toEqual([source.identity.id])
    expect(merged.movedCredentialIds).toEqual([])
    expect(merged.revokedSessionIds).toEqual([source.session.id])
    expect(merged.sourceUser.disabledAt).toEqual(now)
    expect(
      allowedKit.store
        .listIdentities()
        .filter((identity) => identity.id === source.identity.id)
        .map((identity) => identity.userId),
    ).toEqual([target.user.id])
    expect(
      allowedKit.store
        .listSessions()
        .filter((session) => session.userId === source.user.id)
        .map((session) => session.status),
    ).toEqual([SessionStatus.Revoked])
  })

  it('moves password credentials on merge, supports idempotent retry, and keeps audit metadata secret-free', async () => {
    const kit = createInMemoryAuthKit({
      policy: createDefaultAuthPolicy({ allowMergeAccounts: true, requireReAuthFor: [] }),
    })
    const source = await kit.service.signIn({
      assertion: assertion({ providerUserId: 'source-password', email: 'source@example.com' }),
      now,
    })
    const target = await kit.service.signIn({
      assertion: assertion({ providerUserId: 'target-password', email: 'target@example.com' }),
      now,
    })
    const sourceCredential = await kit.service.setPassword({
      userId: source.user.id,
      email: 'source@example.com',
      password: 'source-secret',
      now,
    })

    const merged = await kit.service.mergeAccounts({
      sourceUserId: source.user.id,
      targetUserId: target.user.id,
      sourceSessionToken: source.sessionToken,
      reAuthenticatedAt: now,
      now,
    })

    expect(merged.movedCredentialIds).toEqual([sourceCredential.id])
    expect(merged.revokedSessionIds).toEqual([source.session.id])
    expect(merged.movedIdentityIds).toEqual(expect.arrayContaining([source.identity.id]))
    expect(
      kit.store
        .listCredentials()
        .filter((credential) => credential.id === sourceCredential.id)
        .map((credential) => credential.userId),
    ).toEqual([target.user.id])

    const passwordSignIn = await kit.service.signInWithPassword({
      email: 'source@example.com',
      password: 'source-secret',
      now,
    })

    expect(passwordSignIn.user.id).toBe(target.user.id)

    const retriedMerge = await kit.service.mergeAccounts({
      sourceUserId: source.user.id,
      targetUserId: target.user.id,
      sourceSessionToken: source.sessionToken,
      reAuthenticatedAt: now,
      now,
    })

    expect(retriedMerge.movedIdentityIds).toEqual([])
    expect(retriedMerge.movedCredentialIds).toEqual([])
    expect(retriedMerge.revokedSessionIds).toEqual([])

    const mergeEvents = kit.store
      .listAuditEvents()
      .filter((event) => event.type === AuditEventType.AccountsMerged)

    expect(mergeEvents).toHaveLength(2)
    expect(mergeEvents[0]?.metadata).toMatchObject({
      decision: 'merged',
      sourceUserId: source.user.id,
      movedCredentialIds: [sourceCredential.id],
      revokedSessionIds: [source.session.id],
    })
    expect(mergeEvents[1]?.metadata).toMatchObject({
      decision: 'already-merged',
      sourceUserId: source.user.id,
      movedIdentityIds: [],
      movedCredentialIds: [],
      revokedSessionIds: [],
    })
    expect(JSON.stringify(mergeEvents)).not.toContain('source-secret')
    expect(JSON.stringify(mergeEvents)).not.toContain('source@example.com')
  })

  it('rejects merge credential conflicts without moving data or leaking subjects into audit metadata', async () => {
    const kit = createInMemoryAuthKit({
      policy: createDefaultAuthPolicy({ allowMergeAccounts: true, requireReAuthFor: [] }),
    })
    const source = await kit.service.signIn({
      assertion: assertion({
        providerUserId: 'source-conflict',
        email: 'source-conflict@example.com',
      }),
      now,
    })
    const target = await kit.service.signIn({
      assertion: assertion({
        providerUserId: 'target-conflict',
        email: 'target-conflict@example.com',
      }),
      now,
    })
    const sourceCredential = await kit.service.setPassword({
      userId: source.user.id,
      email: 'source-conflict@example.com',
      password: 'source-conflict-secret',
      now,
    })
    await kit.service.setPassword({
      userId: target.user.id,
      email: 'target-conflict@example.com',
      password: 'target-conflict-secret',
      now,
    })

    const mergeError = await kit.service
      .mergeAccounts({
        sourceUserId: source.user.id,
        targetUserId: target.user.id,
        sourceSessionToken: source.sessionToken,
        reAuthenticatedAt: now,
        now,
      })
      .catch((caught: unknown) => caught)

    expect(mergeError).toMatchObject({ code: UniAuthErrorCode.CredentialAlreadyExists })
    expect(
      kit.store
        .listCredentials()
        .filter((credential) => credential.id === sourceCredential.id)
        .map((credential) => credential.userId),
    ).toEqual([source.user.id])
    expect(
      kit.store.listUsers().find((user) => user.id === source.user.id)?.disabledAt,
    ).toBeUndefined()
    expect(
      kit.store
        .listSessions()
        .filter((session) => session.userId === source.user.id)
        .map((session) => session.status),
    ).toEqual([SessionStatus.Active])

    const denialEvent = [...kit.store.listAuditEvents()]
      .reverse()
      .find((event) => event.type === AuditEventType.PolicyDenied)

    expect(denialEvent?.type).toBe(AuditEventType.PolicyDenied)
    expect(denialEvent?.metadata).toMatchObject({
      reason: 'merge-credential-conflict',
      sourceUserId: source.user.id,
      credentialTypes: ['password'],
    })
    expect(JSON.stringify(denialEvent?.metadata)).not.toContain('source-conflict-secret')
    expect(JSON.stringify(denialEvent?.metadata)).not.toContain('source-conflict@example.com')
    expect(JSON.stringify(denialEvent?.metadata)).not.toContain('target-conflict@example.com')
  })

  it('resolves assertions through a provider registry when requested', async () => {
    const { providerRegistry, service } = createInMemoryAuthKit()
    const provider = new StaticAuthProvider('telegram', {
      providerUserId: 'pending',
      displayName: 'Pending User',
    })

    provider.setAssertion({
      providerUserId: 'tg-1',
      displayName: 'Telegram User',
    })
    providerRegistry.register(provider)

    const result = await service.signIn({
      provider: 'telegram',
      finishInput: { payload: { initData: 'signed' } },
      now,
    })

    expect(result.identity.provider).toBe('telegram')
    expect(result.user.displayName).toBe('Telegram User')
  })
})
