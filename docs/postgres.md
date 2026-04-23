# Postgres Persistence

`@alyldas/uniauth/postgres` provides a reference Postgres adapter for the existing repository ports.
It stays ORM-free and does not ship a hard dependency on `pg`: the application owns the actual
connection pool and passes a `pg.Pool`-compatible object into the adapter.

## Public API

```ts
import {
  POSTGRES_AUTH_SCHEMA_SQL,
  applyPostgresAuthSchema,
  createPostgresAuthStore,
} from '@alyldas/uniauth/postgres'
```

## Runtime Boundary

The application owns:

- the actual `pg` dependency and pool lifecycle;
- connection string and secret loading;
- migrations and schema rollout policy;
- retry policy and pool sizing;
- backup, replication, and failover setup.

UniAuth owns only the repository and transaction wiring around the existing ports.

## Wiring Example

```ts
import { Pool } from 'pg'
import { DefaultAuthService } from '@alyldas/uniauth'
import { createPostgresAuthStore, applyPostgresAuthSchema } from '@alyldas/uniauth/postgres'

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
})

await applyPostgresAuthSchema(pool)

const store = createPostgresAuthStore({ pool })

const service = new DefaultAuthService({
  repos: store,
  transaction: store,
})
```

The adapter expects a `pg.Pool`-compatible object:

- `query(text, values?)`
- `connect()` returning a client with `query(...)` and `release()`

## Schema

`POSTGRES_AUTH_SCHEMA_SQL` creates:

- `uniauth_users`
- `uniauth_identities`
- `uniauth_credentials`
- `uniauth_verifications`
- `uniauth_sessions`
- `uniauth_audit_events`

The reference schema intentionally includes:

- a unique constraint on `(provider, provider_user_id)` in `uniauth_identities`;
- unique constraints on `(type, subject)` and `(type, user_id)` in `uniauth_credentials`;
- partial indexes for verified email and phone lookups on active identities;
- explicit `jsonb` columns for adapter-owned `metadata` and provider `trust`.

## Transaction Model

`PostgresAuthStore` implements `UnitOfWork`. `run()` opens a database transaction, reuses the same
client inside nested UniAuth flows, commits on success, and rolls back on error.

This means link, unlink, merge, session, and verification writes can share the same transaction
boundary when the service calls them through `DefaultAuthService`.

## Security Notes

- Verification secrets remain hashed at rest; the adapter stores only `secret_hash`.
- Trust and metadata fields are stored as `jsonb`, but provider SDK objects should still be reduced
  before they reach UniAuth.
- The adapter does not infer ownership from email or phone outside the core policy flow.
- Migrations remain application-owned. `applyPostgresAuthSchema()` is for reference bootstrap,
  tests, and examples, not for production migration orchestration.
