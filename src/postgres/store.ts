import { AsyncLocalStorage } from 'node:async_hooks'
import type { AuthServiceRepositories, UnitOfWork } from '../contracts.js'
import { createAuditLogRepo } from './store/audit.js'
import { createCredentialRepo } from './store/credentials.js'
import { createIdentityRepo } from './store/identities.js'
import { createSessionRepo } from './store/sessions.js'
import type { PostgresStoreContext } from './store/shared.js'
import { createUserRepo } from './store/users.js'
import { createVerificationRepo } from './store/verifications.js'
import type {
  CreatePostgresAuthStoreOptions,
  PostgresAuthStoreLike,
  PostgresPoolClient,
  PostgresQueryable,
} from './types.js'

export class PostgresAuthStore
  implements PostgresAuthStoreLike, AuthServiceRepositories, UnitOfWork
{
  private readonly transactionScope = new AsyncLocalStorage<PostgresPoolClient>()
  private readonly repoContext: PostgresStoreContext = {
    query: (text, values) => this.query(text, values),
    queryOptionalRow: (text, values, mapRow) => this.queryOptionalRow(text, values, mapRow),
    queryRequiredRow: (text, values, mapRow) => this.queryRequiredRow(text, values, mapRow),
    queryRows: (text, values, mapRow) => this.queryRows(text, values, mapRow),
  }

  constructor(private readonly options: CreatePostgresAuthStoreOptions) {}

  readonly userRepo = createUserRepo(this.repoContext)
  readonly identityRepo = createIdentityRepo(this.repoContext)
  readonly credentialRepo = createCredentialRepo(this.repoContext)
  readonly verificationRepo = createVerificationRepo(this.repoContext)
  readonly sessionRepo = createSessionRepo(this.repoContext)
  readonly auditLogRepo = createAuditLogRepo(this.repoContext)

  async run<T>(operation: () => Promise<T>): Promise<T> {
    const activeTransaction = this.transactionScope.getStore()

    if (activeTransaction) {
      return operation()
    }

    const client = await this.options.pool.connect()

    try {
      await client.query('begin')
      const result = await this.transactionScope.run(client, operation)
      await client.query('commit')
      return result
    } catch (error) {
      try {
        await client.query('rollback')
      } catch {
        // rollback failure should not hide the original error
      }

      throw error
    } finally {
      await client.release()
    }
  }

  private async query(text: string, values?: readonly unknown[]): Promise<void> {
    await this.currentExecutor().query(text, values)
  }

  private async queryOptionalRow<Row extends object, Result>(
    text: string,
    values: readonly unknown[],
    mapRow: (row: Row) => Result,
  ): Promise<Result | undefined> {
    const result = await this.currentExecutor().query<Row>(text, values)
    const row = result.rows[0]
    return row ? mapRow(row) : undefined
  }

  private async queryRequiredRow<Row extends object, Result>(
    text: string,
    values: readonly unknown[],
    mapRow: (row: Row) => Result,
  ): Promise<Result> {
    const result = await this.queryOptionalRow(text, values, mapRow)

    if (!result) {
      throw new Error('Expected a database row to be returned.')
    }

    return result
  }

  private async queryRows<Row extends object, Result>(
    text: string,
    values: readonly unknown[],
    mapRow: (row: Row) => Result,
  ): Promise<readonly Result[]> {
    const result = await this.currentExecutor().query<Row>(text, values)
    return result.rows.map(mapRow)
  }

  private currentExecutor(): PostgresQueryable {
    return this.transactionScope.getStore() ?? this.options.pool
  }
}

export function createPostgresAuthStore(
  options: CreatePostgresAuthStoreOptions,
): PostgresAuthStore {
  return new PostgresAuthStore(options)
}
