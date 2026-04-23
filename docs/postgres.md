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

## Merge Semantics

`mergeAccounts()` on the reference adapter is designed to be atomic:

- active source identities move to the target user;
- source credentials move to the target user;
- the source user is disabled;
- active source sessions are revoked;
- if a target credential of the same type already exists, the merge is rejected before any write is
  committed.

The merge audit payload records only structural data such as moved identity IDs, moved credential
IDs, revoked session IDs, conflicting credential types, and source user IDs. It does not record
credential subjects, passwords, or verification secrets.

## Isolation Assumptions

The reference implementation assumes:

- all UniAuth merge writes run through the same `PostgresAuthStore.run()` transaction boundary;
- the unique constraints on `(provider, provider_user_id)`, `(type, subject)`, and `(type, user_id)`
  remain enabled;
- default Postgres `READ COMMITTED` isolation is acceptable for the reference adapter because the
  uniqueness constraints are the final guard against duplicate identity and credential ownership.

If the application adds external side effects or non-UniAuth writes into the same merge workflow, it
should place them in the same database transaction or choose a stricter isolation level itself.

## Security Notes

- Verification secrets remain hashed at rest; the adapter stores only `secret_hash`.
- Trust and metadata fields are stored as `jsonb`, but provider SDK objects should still be reduced
  before they reach UniAuth.
- The adapter does not infer ownership from email or phone outside the core policy flow.
- Migrations remain application-owned. `applyPostgresAuthSchema()` is for reference bootstrap,
  tests, and examples, not for production migration orchestration.
