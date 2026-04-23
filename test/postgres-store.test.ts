import { describe, expect, it } from 'vitest'
import {
  ProviderTrustLevel,
  UniAuthErrorCode,
  asCredentialId,
  asIdentityId,
  asSessionId,
  asUserId,
  asVerificationId,
} from '../src'
import {
  createPostgresAuthStore,
  type PostgresPool,
  type PostgresPoolClient,
  type PostgresQueryResult,
} from '../src/postgres'

type QueryStep =
  | {
      readonly kind: 'result'
      readonly rows?: readonly object[]
      readonly rowCount?: number | null
    }
  | {
      readonly kind: 'error'
      readonly error: unknown
    }

interface RecordedQuery {
  readonly executor: 'pool' | 'client'
  readonly text: string
  readonly values: readonly unknown[] | undefined
}

interface StubPoolHarness {
  readonly calls: readonly RecordedQuery[]
  readonly connectCount: number
  readonly releaseCount: number
  readonly pool: PostgresPool
  readonly remainingSteps: number
}

function result(rows: readonly object[] = [], rowCount?: number | null): QueryStep {
  return rowCount === undefined
    ? {
        kind: 'result',
        rows,
      }
    : {
        kind: 'result',
        rows,
        rowCount,
      }
}

function failure(error: unknown): QueryStep {
  return {
    kind: 'error',
    error,
  }
}

function createStubPool(steps: readonly QueryStep[]): StubPoolHarness {
  const queue = [...steps]
  const calls: RecordedQuery[] = []
  let connectCount = 0
  let releaseCount = 0

  const runQuery =
    (executor: 'pool' | 'client') =>
    async <Row extends object = Record<string, unknown>>(
      text: string,
      values?: readonly unknown[],
    ): Promise<PostgresQueryResult<Row>> => {
      calls.push({ executor, text, values })

      const next = queue.shift()

      if (!next) {
        throw new Error(`Unexpected query: ${text}`)
      }

      if (next.kind === 'error') {
        throw next.error
      }

      const rows = (next.rows ?? []) as readonly Row[]

      return {
        rows,
        rowCount: next.rowCount ?? rows.length,
      }
    }

  const client: PostgresPoolClient = {
    query: runQuery('client'),
    async release() {
      releaseCount += 1
    },
  }

  const pool: PostgresPool = {
    query: runQuery('pool'),
    async connect() {
      connectCount += 1
      return client
    },
  }

  return {
    get calls() {
      return calls
    },
    get connectCount() {
      return connectCount
    },
    get releaseCount() {
      return releaseCount
    },
    pool,
    get remainingSteps() {
      return queue.length
    },
  }
}

function userRow(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    id: 'user-1',
    display_name: null,
    email: null,
    phone: null,
    created_at: '2026-01-01T00:00:00.000Z',
    updated_at: '2026-01-01T00:00:00.000Z',
    disabled_at: null,
    metadata: null,
    ...overrides,
  }
}

function identityRow(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    id: 'identity-1',
    user_id: 'user-1',
    provider: 'oidc',
    provider_user_id: 'provider-user-1',
    status: 'active',
    email: 'user@example.com',
    email_verified: true,
    phone: null,
    phone_verified: null,
    trust: null,
    created_at: '2026-01-01T00:00:00.000Z',
    updated_at: '2026-01-01T00:00:00.000Z',
    disabled_at: null,
    metadata: null,
    ...overrides,
  }
}

function credentialRow(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    id: 'credential-1',
    user_id: 'user-1',
    type: 'password',
    subject: 'user@example.com',
    password_hash: 'hashed-password',
    created_at: '2026-01-01T00:00:00.000Z',
    updated_at: '2026-01-01T00:00:00.000Z',
    metadata: null,
    ...overrides,
  }
}

function verificationRow(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    id: 'verification-1',
    purpose: 'sign-in',
    target: 'user@example.com',
    provider: null,
    channel: null,
    secret_hash: 'hashed-secret',
    status: 'pending',
    created_at: '2026-01-01T00:00:00.000Z',
    expires_at: '2026-01-01T00:10:00.000Z',
    consumed_at: null,
    metadata: null,
    ...overrides,
  }
}

function sessionRow(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    id: 'session-1',
    user_id: 'user-1',
    status: 'active',
    created_at: '2026-01-01T00:00:00.000Z',
    expires_at: '2026-01-31T00:00:00.000Z',
    revoked_at: null,
    last_seen_at: null,
    metadata: null,
    ...overrides,
  }
}

describe('PostgresAuthStore unit coverage', () => {
  it('maps row payloads from the pool into public entities', async () => {
    const harness = createStubPool([
      result([
        userRow({
          display_name: 'Alice',
          email: 'alice@example.com',
          phone: '+10000000000',
          created_at: new Date('2026-01-01T00:00:00.000Z'),
          updated_at: '2026-01-01T00:01:00.000Z',
          disabled_at: '2026-01-01T00:02:00.000Z',
          metadata: '{"role":"admin"}',
        }),
      ]),
      result([
        identityRow({
          trust: JSON.stringify({
            level: ProviderTrustLevel.Trusted,
            signals: [' device ', '', 'device', 'federated'],
            metadata: { source: 'oidc' },
          }),
          phone: '+10000000000',
          phone_verified: true,
          disabled_at: '2026-01-01T00:03:00.000Z',
          metadata: { state: 'seeded' },
        }),
      ]),
      result([
        {
          ...identityRow(),
          id: 'identity-2',
          provider_user_id: 'provider-user-2',
          email_verified: null,
          trust: {
            level: ProviderTrustLevel.Neutral,
            signals: [],
            metadata: null,
          },
        },
      ]),
      result([
        {
          ...identityRow(),
          id: 'identity-3',
          provider_user_id: 'provider-user-3',
          trust: {
            level: ProviderTrustLevel.Untrusted,
          },
        },
      ]),
      result([
        {
          ...identityRow({
            id: 'identity-4',
            provider_user_id: 'provider-user-4',
            phone: '+12223334444',
            phone_verified: true,
          }),
          trust: null,
        },
      ]),
      result([
        {
          ...identityRow({
            id: 'identity-5',
            provider_user_id: 'provider-user-5',
          }),
          trust: {
            level: ProviderTrustLevel.Trusted,
            metadata: null,
          },
        },
      ]),
      result([
        credentialRow({
          created_at: new Date('2026-01-01T00:00:00.000Z'),
          updated_at: '2026-01-01T00:04:00.000Z',
          metadata: '{"source":"import"}',
        }),
      ]),
      result([
        verificationRow({
          provider: 'email-otp',
          channel: 'email',
          consumed_at: '2026-01-01T00:05:00.000Z',
          metadata: { attempt: 1 },
        }),
      ]),
      result([
        sessionRow({
          revoked_at: '2026-01-01T00:06:00.000Z',
          last_seen_at: new Date('2026-01-01T00:07:00.000Z'),
        }),
      ]),
    ])
    const store = createPostgresAuthStore({ pool: harness.pool })

    await expect(store.userRepo.findById(asUserId('user-1'))).resolves.toMatchObject({
      id: asUserId('user-1'),
      displayName: 'Alice',
      email: 'alice@example.com',
      phone: '+10000000000',
      metadata: { role: 'admin' },
    })
    await expect(store.identityRepo.findById(asIdentityId('identity-1'))).resolves.toMatchObject({
      id: asIdentityId('identity-1'),
      trust: {
        level: ProviderTrustLevel.Trusted,
        signals: ['device', 'federated'],
        metadata: { source: 'oidc' },
      },
      metadata: { state: 'seeded' },
    })
    await expect(
      store.identityRepo.findByProviderUserId('oidc', 'provider-user-2'),
    ).resolves.toMatchObject({
      id: asIdentityId('identity-2'),
      trust: { level: ProviderTrustLevel.Neutral },
    })
    await expect(store.identityRepo.findByVerifiedEmail('user@example.com')).resolves.toMatchObject(
      [
        {
          id: asIdentityId('identity-3'),
          trust: { level: ProviderTrustLevel.Untrusted },
        },
      ],
    )
    await expect(store.identityRepo.findByVerifiedPhone('+12223334444')).resolves.toMatchObject([
      {
        id: asIdentityId('identity-4'),
      },
    ])
    await expect(store.identityRepo.listByUserId(asUserId('user-1'))).resolves.toMatchObject([
      {
        id: asIdentityId('identity-5'),
        trust: { level: ProviderTrustLevel.Trusted },
      },
    ])
    await expect(
      store.credentialRepo.findPasswordByEmail('user@example.com'),
    ).resolves.toMatchObject({
      id: asCredentialId('credential-1'),
      metadata: { source: 'import' },
    })
    await expect(
      store.verificationRepo.findById(asVerificationId('verification-1')),
    ).resolves.toMatchObject({
      id: asVerificationId('verification-1'),
      provider: 'email-otp',
      channel: 'email',
      metadata: { attempt: 1 },
    })
    await expect(store.sessionRepo.findById(asSessionId('session-1'))).resolves.toMatchObject({
      id: asSessionId('session-1'),
      status: 'active',
    })

    expect(harness.remainingSteps).toBe(0)
  })

  it('maps write failures into domain and generic errors', async () => {
    const identityWriteError = new Error('identity write failed')
    const credentialWriteError = new Error('credential write failed')
    const harness = createStubPool([
      failure({ code: '23505' }),
      failure('identity-unknown'),
      result([identityRow()]),
      failure(identityWriteError),
      failure({ code: '23505' }),
      failure('credential-unknown'),
      result([credentialRow()]),
      failure(credentialWriteError),
    ])
    const store = createPostgresAuthStore({ pool: harness.pool })

    await expect(
      store.identityRepo.create({
        id: asIdentityId('identity-create-1'),
        userId: asUserId('user-1'),
        provider: 'oidc',
        providerUserId: 'provider-user-create-1',
        status: 'active',
        createdAt: new Date('2026-01-01T00:00:00.000Z'),
        updatedAt: new Date('2026-01-01T00:00:00.000Z'),
      }),
    ).rejects.toMatchObject({
      code: UniAuthErrorCode.IdentityAlreadyLinked,
    })
    await expect(
      store.identityRepo.create({
        id: asIdentityId('identity-create-2'),
        userId: asUserId('user-1'),
        provider: 'oidc',
        providerUserId: 'provider-user-create-2',
        status: 'active',
        createdAt: new Date('2026-01-01T00:00:00.000Z'),
        updatedAt: new Date('2026-01-01T00:00:00.000Z'),
      }),
    ).rejects.toThrow('Unknown Postgres error.')
    await expect(
      store.identityRepo.update(asIdentityId('identity-1'), {
        providerUserId: 'updated-provider-user',
      }),
    ).rejects.toBe(identityWriteError)

    await expect(
      store.credentialRepo.create({
        id: asCredentialId('credential-create-1'),
        userId: asUserId('user-1'),
        type: 'password',
        subject: 'user@example.com',
        passwordHash: 'hash',
        createdAt: new Date('2026-01-01T00:00:00.000Z'),
        updatedAt: new Date('2026-01-01T00:00:00.000Z'),
      }),
    ).rejects.toMatchObject({
      code: UniAuthErrorCode.CredentialAlreadyExists,
    })
    await expect(
      store.credentialRepo.create({
        id: asCredentialId('credential-create-2'),
        userId: asUserId('user-1'),
        type: 'password',
        subject: 'user@example.com',
        passwordHash: 'hash',
        createdAt: new Date('2026-01-01T00:00:00.000Z'),
        updatedAt: new Date('2026-01-01T00:00:00.000Z'),
      }),
    ).rejects.toThrow('Unknown Postgres error.')
    await expect(
      store.credentialRepo.update(asCredentialId('credential-1'), { passwordHash: 'new-hash' }),
    ).rejects.toBe(credentialWriteError)

    expect(harness.remainingSteps).toBe(0)
  })

  it('surfaces invalid database payloads and missing required rows', async () => {
    const harness = createStubPool([
      result(),
      result([
        userRow({
          created_at: 'not-a-date',
        }),
      ]),
      result([
        userRow({
          metadata: '[]',
        }),
      ]),
      result([
        identityRow({
          trust: { level: 'invalid-trust-level' },
        }),
      ]),
      result([
        identityRow({
          trust: { level: ProviderTrustLevel.Trusted, signals: [1] },
        }),
      ]),
      result([
        identityRow({
          trust: { level: ProviderTrustLevel.Trusted, metadata: [] },
        }),
      ]),
    ])
    const store = createPostgresAuthStore({ pool: harness.pool })

    await expect(
      store.userRepo.create({
        id: asUserId('user-create-1'),
        createdAt: new Date('2026-01-01T00:00:00.000Z'),
        updatedAt: new Date('2026-01-01T00:00:00.000Z'),
      }),
    ).rejects.toThrow('Expected a database row to be returned.')
    await expect(store.userRepo.findById(asUserId('user-1'))).rejects.toThrow(
      'Invalid date value returned from Postgres.',
    )
    await expect(store.userRepo.findById(asUserId('user-1'))).rejects.toThrow(
      'Expected a JSON object returned from Postgres.',
    )
    await expect(store.identityRepo.findById(asIdentityId('identity-1'))).rejects.toThrow(
      'Invalid provider trust payload returned from Postgres.',
    )
    await expect(store.identityRepo.findById(asIdentityId('identity-1'))).rejects.toThrow(
      'Invalid provider trust signals returned from Postgres.',
    )
    await expect(store.identityRepo.findById(asIdentityId('identity-1'))).rejects.toThrow(
      'Expected a JSON object returned from Postgres.',
    )

    expect(harness.remainingSteps).toBe(0)
  })

  it('runs transactional operations through the client and handles rollbacks', async () => {
    const successHarness = createStubPool([
      result(),
      result([userRow({ id: 'transaction-user' })]),
      result(),
    ])
    const successStore = createPostgresAuthStore({ pool: successHarness.pool })

    await expect(
      successStore.run(async () => {
        await expect(
          successStore.userRepo.findById(asUserId('transaction-user')),
        ).resolves.toMatchObject({
          id: asUserId('transaction-user'),
        })

        return successStore.run(async () => 'nested-ok')
      }),
    ).resolves.toBe('nested-ok')

    expect(successHarness.connectCount).toBe(1)
    expect(successHarness.releaseCount).toBe(1)
    expect(successHarness.calls.map((call) => call.executor)).toEqual([
      'client',
      'client',
      'client',
    ])

    const rollbackHarness = createStubPool([result(), result()])
    const rollbackStore = createPostgresAuthStore({ pool: rollbackHarness.pool })
    const originalError = new Error('transaction failed')

    await expect(
      rollbackStore.run(async () => {
        throw originalError
      }),
    ).rejects.toBe(originalError)

    expect(rollbackHarness.connectCount).toBe(1)
    expect(rollbackHarness.releaseCount).toBe(1)
    expect(rollbackHarness.calls.map((call) => call.text)).toEqual(['begin', 'rollback'])

    const rollbackFailureHarness = createStubPool([result(), failure(new Error('rollback failed'))])
    const rollbackFailureStore = createPostgresAuthStore({ pool: rollbackFailureHarness.pool })
    const rollbackOriginalError = new Error('still fail')

    await expect(
      rollbackFailureStore.run(async () => {
        throw rollbackOriginalError
      }),
    ).rejects.toBe(rollbackOriginalError)

    expect(rollbackFailureHarness.connectCount).toBe(1)
    expect(rollbackFailureHarness.releaseCount).toBe(1)
    expect(rollbackFailureHarness.calls.map((call) => call.text)).toEqual(['begin', 'rollback'])
  })
})
