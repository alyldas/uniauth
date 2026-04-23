import { newDb } from 'pg-mem'
import { afterEach, describe, expect, it } from 'vitest'
import {
  AuthIdentityStatus,
  ProviderTrustLevel,
  SessionStatus,
  UniAuthErrorCode,
  VerificationStatus,
  VerificationPurpose,
  asAuditEventId,
  asCredentialId,
  asIdentityId,
  asSessionId,
  asUserId,
  asVerificationId,
  createAuthService,
  createDefaultAuthPolicy,
  createSequentialIdGenerator,
  type Credential,
} from '../src'
import {
  applyPostgresAuthSchema,
  createPostgresAuthStore,
  type PostgresPool,
} from '../src/postgres'
import { InMemoryPasswordHasher, StaticAuthProvider } from '../src/testing'
import { identity, now, user } from './helpers.js'

interface PostgresTestKit {
  readonly pool: PostgresPool & { end(): Promise<void> }
  readonly store: ReturnType<typeof createPostgresAuthStore>
  readonly service: ReturnType<typeof createAuthService>
}

const openPools = new Set<{ end(): Promise<void> }>()

afterEach(async () => {
  for (const pool of openPools) {
    await pool.end()
  }

  openPools.clear()
})

async function createPostgresTestKit(): Promise<PostgresTestKit> {
  const database = newDb({ autoCreateForeignKeyIndices: true })
  const pg = database.adapters.createPg()
  const pool = new pg.Pool() as PostgresPool & { end(): Promise<void> }

  openPools.add(pool)

  await applyPostgresAuthSchema(pool)

  const store = createPostgresAuthStore({ pool })
  const provider = new StaticAuthProvider('oidc', {
    providerUserId: 'oidc-user',
    email: 'oidc@example.com',
    emailVerified: true,
    trust: {
      level: ProviderTrustLevel.Trusted,
      signals: ['oidc-email-verified'],
    },
  })
  const providerRegistry = {
    async get(id: string) {
      return id === provider.id ? provider : undefined
    },
  }

  const service = createAuthService({
    repos: store,
    transaction: store,
    providerRegistry,
    idGenerator: createSequentialIdGenerator('pg'),
    passwordHasher: new InMemoryPasswordHasher(),
    policy: createDefaultAuthPolicy({
      allowAutoLink: true,
      allowMergeAccounts: true,
      requireReAuthFor: [],
    }),
  })

  return {
    pool,
    store,
    service,
  }
}

describe('Postgres reference persistence', () => {
  it('applies the schema and supports repository round-trips', async () => {
    const { pool, store } = await createPostgresTestKit()
    const idGenerator = createSequentialIdGenerator('pg-repo')
    const createdUser = await store.userRepo.create(user('pg-user-1'))
    const createdIdentity = await store.identityRepo.create(
      identity({
        id: idGenerator.identityId(),
        userId: createdUser.id,
        provider: 'email',
        providerUserId: 'pg-user@example.com',
        email: 'pg-user@example.com',
        emailVerified: true,
        trust: {
          level: ProviderTrustLevel.Trusted,
          signals: ['seeded'],
        },
      }),
    )
    const credential: Credential = {
      id: asCredentialId('pg-credential-1'),
      userId: createdUser.id,
      type: 'password',
      subject: 'pg-user@example.com',
      passwordHash: 'hashed-password',
      createdAt: now,
      updatedAt: now,
    }

    await store.credentialRepo.create(credential)
    await store.sessionRepo.create({
      id: createSequentialIdGenerator('pg-session').sessionId(),
      userId: createdUser.id,
      status: 'active',
      createdAt: now,
      expiresAt: new Date('2026-01-31T00:00:00.000Z'),
    })
    await store.verificationRepo.create({
      id: createSequentialIdGenerator('pg-verification').verificationId(),
      purpose: VerificationPurpose.SignIn,
      target: 'pg-user@example.com',
      secretHash: 'hashed-secret',
      status: 'pending',
      createdAt: now,
      expiresAt: new Date('2026-01-01T00:10:00.000Z'),
    })
    await store.auditLogRepo.append({
      id: asAuditEventId('pg-audit-1'),
      type: 'auth.sign_in',
      occurredAt: now,
      userId: createdUser.id,
      identityId: createdIdentity.id,
    })

    expect(await store.userRepo.findById(createdUser.id)).toMatchObject({
      id: createdUser.id,
    })
    expect(
      await store.identityRepo.findByProviderUserId('email', 'pg-user@example.com'),
    ).toMatchObject({
      id: createdIdentity.id,
      trust: {
        level: ProviderTrustLevel.Trusted,
        signals: ['seeded'],
      },
    })
    expect(await store.identityRepo.findByVerifiedEmail('pg-user@example.com')).toHaveLength(1)
    expect(await store.credentialRepo.findPasswordByEmail('pg-user@example.com')).toMatchObject({
      id: credential.id,
    })
    expect(await store.sessionRepo.listByUserId(createdUser.id)).toHaveLength(1)
    expect(
      await pool.query<{ count: number }>(
        'select count(*)::int as count from uniauth_audit_events',
      ),
    ).toMatchObject({
      rows: [{ count: 1 }],
    })

    expect(
      await store.identityRepo
        .create(
          identity({
            id: createSequentialIdGenerator('duplicate-identity').identityId(),
            userId: createdUser.id,
            provider: 'email',
            providerUserId: 'pg-user@example.com',
          }),
        )
        .catch((caught: unknown) => caught),
    ).toMatchObject({ code: UniAuthErrorCode.IdentityAlreadyLinked })
    expect(
      await store.credentialRepo
        .create({
          ...credential,
          id: asCredentialId('pg-credential-2'),
        })
        .catch((caught: unknown) => caught),
    ).toMatchObject({ code: UniAuthErrorCode.CredentialAlreadyExists })
  })

  it('runs core auth flows on top of the Postgres store', async () => {
    const { pool, service } = await createPostgresTestKit()

    const first = await service.signIn({
      provider: 'oidc',
      finishInput: { payload: { code: 'oidc-code' } },
      now,
    })
    const second = await service.signIn({
      assertion: {
        provider: 'email',
        providerUserId: 'oidc@example.com',
        email: 'oidc@example.com',
        emailVerified: true,
        trust: {
          level: ProviderTrustLevel.Trusted,
          signals: ['first-party-email'],
        },
      },
      now,
    })
    const verification = await service.createVerification({
      purpose: VerificationPurpose.SignIn,
      target: 'oidc@example.com',
      secret: '123456',
      now,
    })

    expect(first.user.id).toBe(second.user.id)
    expect(second.isNewIdentity).toBe(true)

    const storedVerification = await pool.query<{ secret_hash: string }>(
      'select secret_hash from uniauth_verifications where id = $1',
      [verification.verification.id],
    )

    expect(storedVerification.rows[0]?.secret_hash).toBeTypeOf('string')
    expect(storedVerification.rows[0]?.secret_hash).not.toBe('123456')
  })

  it('persists writes executed inside the transaction boundary', async () => {
    const { store } = await createPostgresTestKit()
    const transactionUser = user('tx-user-1')

    const created = await store.run(async () => store.userRepo.create(transactionUser))

    expect(created.id).toBe(transactionUser.id)
    expect(await store.userRepo.findById(transactionUser.id)).toMatchObject({
      id: transactionUser.id,
    })
  })

  it('supports update flows and not-found branches across repositories', async () => {
    const { store } = await createPostgresTestKit()
    const createdUser = await store.userRepo.create({
      ...user('pg-user-update'),
      displayName: 'Before',
      email: 'before@example.com',
      phone: '+10000000000',
      metadata: { state: 'before' },
    })
    const createdIdentity = await store.identityRepo.create(
      identity({
        id: asIdentityId('pg-identity-update'),
        userId: createdUser.id,
        provider: 'oidc',
        providerUserId: 'oidc-update-user',
        email: 'before@example.com',
        emailVerified: false,
        phone: '+10000000000',
        phoneVerified: false,
        trust: {
          level: ProviderTrustLevel.Neutral,
          signals: [],
        },
        metadata: { state: 'before' },
      }),
    )
    const createdCredential = await store.credentialRepo.create({
      id: asCredentialId('pg-credential-update'),
      userId: createdUser.id,
      type: 'password',
      subject: 'before@example.com',
      passwordHash: 'before-hash',
      createdAt: now,
      updatedAt: now,
      metadata: { state: 'before' },
    })
    const createdVerification = await store.verificationRepo.create({
      id: asVerificationId('pg-verification-update'),
      purpose: VerificationPurpose.SignIn,
      target: 'before@example.com',
      provider: 'email-otp',
      channel: 'email',
      secretHash: 'before-secret-hash',
      status: VerificationStatus.Pending,
      createdAt: now,
      expiresAt: new Date('2026-01-01T00:30:00.000Z'),
      metadata: { state: 'before' },
    })
    const createdSession = await store.sessionRepo.create({
      id: asSessionId('pg-session-update'),
      userId: createdUser.id,
      status: SessionStatus.Active,
      createdAt: now,
      expiresAt: new Date('2026-01-31T00:00:00.000Z'),
      metadata: { state: 'before' },
    })

    expect(await store.userRepo.update(createdUser.id, {})).toMatchObject({
      id: createdUser.id,
      displayName: 'Before',
    })

    const updatedUser = await store.userRepo.update(createdUser.id, {
      displayName: 'After',
      updatedAt: new Date('2026-01-01T00:05:00.000Z'),
      metadata: { state: 'after' },
    })

    expect(updatedUser).toMatchObject({
      id: createdUser.id,
      displayName: 'After',
      metadata: { state: 'after' },
    })

    const clearedUserPhone = await store.userRepo.update(createdUser.id, {
      phone: undefined,
      updatedAt: new Date('2026-01-01T00:05:30.000Z'),
    } as unknown as Parameters<typeof store.userRepo.update>[1])

    expect(clearedUserPhone).not.toHaveProperty('phone')

    await expect(store.userRepo.update(asUserId('missing-user'), {})).rejects.toMatchObject({
      code: UniAuthErrorCode.UserNotFound,
    })

    expect(await store.identityRepo.findById(createdIdentity.id)).toMatchObject({
      id: createdIdentity.id,
      trust: { level: ProviderTrustLevel.Neutral },
    })
    expect(await store.identityRepo.update(createdIdentity.id, {})).toMatchObject({
      id: createdIdentity.id,
      status: AuthIdentityStatus.Active,
    })

    const updatedIdentity = await store.identityRepo.update(createdIdentity.id, {
      status: AuthIdentityStatus.Disabled,
      phoneVerified: true,
      trust: {
        level: ProviderTrustLevel.Untrusted,
      },
      updatedAt: new Date('2026-01-01T00:06:00.000Z'),
      disabledAt: new Date('2026-01-01T00:07:00.000Z'),
      metadata: { state: 'after' },
    })

    expect(updatedIdentity).toMatchObject({
      id: createdIdentity.id,
      status: AuthIdentityStatus.Disabled,
      phoneVerified: true,
      trust: { level: ProviderTrustLevel.Untrusted },
      metadata: { state: 'after' },
    })

    await expect(
      store.identityRepo.update(asIdentityId('missing-identity'), {}),
    ).rejects.toMatchObject({
      code: UniAuthErrorCode.IdentityNotFound,
    })

    expect(await store.credentialRepo.findPasswordByUserId(createdUser.id)).toMatchObject({
      id: createdCredential.id,
    })
    expect(await store.credentialRepo.update(createdCredential.id, {})).toMatchObject({
      id: createdCredential.id,
    })

    const updatedCredential = await store.credentialRepo.update(createdCredential.id, {
      subject: 'after@example.com',
      passwordHash: 'after-hash',
      updatedAt: new Date('2026-01-01T00:08:00.000Z'),
      metadata: { state: 'after' },
    })

    expect(updatedCredential).toMatchObject({
      id: createdCredential.id,
      subject: 'after@example.com',
      passwordHash: 'after-hash',
      metadata: { state: 'after' },
    })

    await expect(
      store.credentialRepo.update(asCredentialId('missing-credential'), {}),
    ).rejects.toMatchObject({
      code: UniAuthErrorCode.CredentialNotFound,
    })

    expect(await store.verificationRepo.findById(createdVerification.id)).toMatchObject({
      id: createdVerification.id,
      provider: 'email-otp',
      channel: 'email',
    })
    expect(await store.verificationRepo.update(createdVerification.id, {})).toMatchObject({
      id: createdVerification.id,
      status: VerificationStatus.Pending,
    })

    const updatedVerification = await store.verificationRepo.update(createdVerification.id, {
      status: VerificationStatus.Consumed,
      expiresAt: new Date('2026-01-01T00:45:00.000Z'),
      consumedAt: new Date('2026-01-01T00:15:00.000Z'),
      metadata: { state: 'after' },
    })

    expect(updatedVerification).toMatchObject({
      id: createdVerification.id,
      status: VerificationStatus.Consumed,
      metadata: { state: 'after' },
    })

    await expect(
      store.verificationRepo.update(asVerificationId('missing-verification'), {}),
    ).rejects.toMatchObject({
      code: UniAuthErrorCode.VerificationNotFound,
    })

    expect(await store.sessionRepo.findById(createdSession.id)).toMatchObject({
      id: createdSession.id,
      status: SessionStatus.Active,
    })
    expect(await store.sessionRepo.update(createdSession.id, {})).toMatchObject({
      id: createdSession.id,
      status: SessionStatus.Active,
    })

    const updatedSession = await store.sessionRepo.update(createdSession.id, {
      status: SessionStatus.Revoked,
      expiresAt: new Date('2026-02-01T00:00:00.000Z'),
      revokedAt: new Date('2026-01-01T00:20:00.000Z'),
      lastSeenAt: new Date('2026-01-01T00:10:00.000Z'),
      metadata: { state: 'after' },
    })

    expect(updatedSession).toMatchObject({
      id: createdSession.id,
      status: SessionStatus.Revoked,
      metadata: { state: 'after' },
    })

    await expect(
      store.sessionRepo.update(asSessionId('missing-session'), {}),
    ).rejects.toMatchObject({
      code: UniAuthErrorCode.SessionNotFound,
    })
  })

  it('moves password credentials during merge and supports idempotent retries on Postgres', async () => {
    const { service, store } = await createPostgresTestKit()
    const source = await service.signIn({
      assertion: {
        provider: 'email',
        providerUserId: 'pg-merge-source',
        email: 'pg-merge-source@example.com',
        emailVerified: true,
      },
      now,
    })
    const target = await service.signIn({
      assertion: {
        provider: 'email',
        providerUserId: 'pg-merge-target',
        email: 'pg-merge-target@example.com',
        emailVerified: true,
      },
      now,
    })
    const sourceCredential = await service.setPassword({
      userId: source.user.id,
      email: 'pg-merge-source@example.com',
      password: 'pg-merge-secret',
      now,
    })

    const merged = await service.mergeAccounts({
      sourceUserId: source.user.id,
      targetUserId: target.user.id,
      reAuthenticatedAt: now,
      now,
    })

    expect(merged.movedCredentialIds).toEqual([sourceCredential.id])
    expect(merged.revokedSessionIds).toEqual([source.session.id])
    expect(await store.credentialRepo.listByUserId(target.user.id)).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          id: sourceCredential.id,
          userId: target.user.id,
        }),
      ]),
    )

    const passwordSignIn = await service.signInWithPassword({
      email: 'pg-merge-source@example.com',
      password: 'pg-merge-secret',
      now,
    })

    expect(passwordSignIn.user.id).toBe(target.user.id)

    const retriedMerge = await service.mergeAccounts({
      sourceUserId: source.user.id,
      targetUserId: target.user.id,
      reAuthenticatedAt: now,
      now,
    })

    expect(retriedMerge.movedIdentityIds).toEqual([])
    expect(retriedMerge.movedCredentialIds).toEqual([])
    expect(retriedMerge.revokedSessionIds).toEqual([])
  })

  it('rejects merge credential conflicts on Postgres without partial writes', async () => {
    const { service, store } = await createPostgresTestKit()
    const source = await service.signIn({
      assertion: {
        provider: 'email',
        providerUserId: 'pg-conflict-source',
        email: 'pg-conflict-source@example.com',
        emailVerified: true,
      },
      now,
    })
    const target = await service.signIn({
      assertion: {
        provider: 'email',
        providerUserId: 'pg-conflict-target',
        email: 'pg-conflict-target@example.com',
        emailVerified: true,
      },
      now,
    })
    const sourceCredential = await service.setPassword({
      userId: source.user.id,
      email: 'pg-conflict-source@example.com',
      password: 'pg-conflict-source-secret',
      now,
    })
    await service.setPassword({
      userId: target.user.id,
      email: 'pg-conflict-target@example.com',
      password: 'pg-conflict-target-secret',
      now,
    })

    await expect(
      service.mergeAccounts({
        sourceUserId: source.user.id,
        targetUserId: target.user.id,
        reAuthenticatedAt: now,
        now,
      }),
    ).rejects.toMatchObject({
      code: UniAuthErrorCode.CredentialAlreadyExists,
    })

    expect(await store.userRepo.findById(source.user.id)).toMatchObject({
      id: source.user.id,
    })
    expect(await store.credentialRepo.listByUserId(source.user.id)).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          id: sourceCredential.id,
          userId: source.user.id,
        }),
      ]),
    )
    expect(
      (await store.identityRepo.listByUserId(source.user.id)).map((identity) => identity.userId),
    ).toEqual(expect.arrayContaining([source.user.id]))
    expect(
      (await store.sessionRepo.listByUserId(source.user.id)).map((session) => session.status),
    ).toEqual([SessionStatus.Active])
  })
})
