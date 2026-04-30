import { newDb } from 'pg-mem'
import { afterEach } from 'vitest'
import {
  ProviderTrustLevel,
  createAuthService,
  createDefaultAuthPolicy,
  createSequentialIdGenerator,
  type AuthPolicy,
} from '../../src'
import {
  applyPostgresAuthSchema,
  createPostgresAuthStore,
  type PostgresPool,
} from '../../src/postgres'
import { InMemoryPasswordHasher, StaticAuthProvider } from '../../src/testing'
import { now } from '../helpers.js'

interface PostgresTestKitOptions {
  readonly policy?: AuthPolicy
}

export interface PostgresTestKit {
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

  const service = createAuthService({
    repos: store,
    transaction: store,
    providerRegistry,
    idGenerator: createSequentialIdGenerator('pg'),
    passwordHasher: new InMemoryPasswordHasher(),
    policy:
      options.policy ??
      createDefaultAuthPolicy({
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

export { now }
