import type { AuthServiceRepositories, UnitOfWork } from '../ports.js'

export interface PostgresQueryResult<Row extends object = Record<string, unknown>> {
  readonly rows: readonly Row[]
  readonly rowCount: number | null
}

export interface PostgresQueryable {
  query<Row extends object = Record<string, unknown>>(
    text: string,
    values?: readonly unknown[],
  ): Promise<PostgresQueryResult<Row>>
}

export interface PostgresPoolClient extends PostgresQueryable {
  release(): void | Promise<void>
}

export interface PostgresPool extends PostgresQueryable {
  connect(): Promise<PostgresPoolClient>
}

export interface CreatePostgresAuthStoreOptions {
  readonly pool: PostgresPool
}

export interface PostgresAuthStoreLike extends AuthServiceRepositories, UnitOfWork {}
