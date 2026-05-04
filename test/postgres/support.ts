import { newDb } from 'pg-mem'
import { afterEach } from 'vitest'
import {
  ProviderTrustLevel,
  createAuthService,
  createDefaultAuthPolicy,
  createSequentialIdGenerator,
  type Clock,
  type AuthPolicy,
} from '../../src'
import {
  applyPostgresAuthSchema,
  createPostgresAuthStore,
  type PostgresPool,
} from '../../src/postgres'
import {
  InMemoryEmailSender,
  InMemoryPasswordHasher,
  InMemorySmsSender,
  StaticAuthProvider,
} from '../../src/testing'
import { now } from '../helpers.js'

interface PostgresTestKitOptions {
  readonly policy?: AuthPolicy
  readonly clock?: Clock
  readonly verificationResendCooldownSeconds?: number
}

export interface PostgresTestKit {
  readonly pool: PostgresPool & { end(): Promise<void> }
  readonly store: ReturnType<typeof createPostgresAuthStore>
  readonly service: ReturnType<typeof createAuthService>
  readonly emailSender: InMemoryEmailSender
  readonly smsSender: InMemorySmsSender
}

const openPools = new Set<{ end(): Promise<void> }>()

afterEach(async () => {
  for (const pool of openPools) {
    await pool.end()
  }

  openPools.clear()
})

export async function createPostgresTestKit(
  options: PostgresTestKitOptions = {},
): Promise<PostgresTestKit> {
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
  const emailSender = new InMemoryEmailSender()
  const smsSender = new InMemorySmsSender()

  const service = createAuthService({
    repos: store,
    transaction: store,
    providerRegistry,
    emailSender,
    smsSender,
    idGenerator: createSequentialIdGenerator('pg'),
    passwordHasher: new InMemoryPasswordHasher(),
    ...(options.verificationResendCooldownSeconds !== undefined
      ? { verificationResendCooldownSeconds: options.verificationResendCooldownSeconds }
      : {}),
    policy:
      options.policy ??
      createDefaultAuthPolicy({
        allowAutoLink: true,
        allowMergeAccounts: true,
        requireReAuthFor: [],
      }),
    ...(options.clock ? { clock: options.clock } : {}),
  })

  return {
    pool,
    store,
    service,
    emailSender,
    smsSender,
  }
}

export { now }
