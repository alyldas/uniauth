import type { PostgresQueryable } from './types.js'

const schemaStatements = [
  `create table if not exists uniauth_users (
    id text primary key,
    display_name text,
    email text,
    phone text,
    created_at timestamptz not null,
    updated_at timestamptz not null,
    disabled_at timestamptz,
    metadata jsonb
  )`,
  `create table if not exists uniauth_identities (
    id text primary key,
    user_id text not null references uniauth_users(id) on delete restrict,
    provider text not null,
    provider_user_id text not null,
    status text not null check (status in ('active', 'disabled')),
    email text,
    email_verified boolean,
    phone text,
    phone_verified boolean,
    trust jsonb,
    created_at timestamptz not null,
    updated_at timestamptz not null,
    disabled_at timestamptz,
    metadata jsonb,
    constraint uniauth_identities_provider_user_key unique (provider, provider_user_id)
  )`,
  `create index if not exists uniauth_identities_user_idx on uniauth_identities (user_id)`,
  `create index if not exists uniauth_identities_verified_email_idx
    on uniauth_identities (email)
    where status = 'active' and email_verified = true and email is not null`,
  `create index if not exists uniauth_identities_verified_phone_idx
    on uniauth_identities (phone)
    where status = 'active' and phone_verified = true and phone is not null`,
  `create table if not exists uniauth_credentials (
    id text primary key,
    user_id text not null references uniauth_users(id) on delete restrict,
    type text not null,
    subject text not null,
    password_hash text not null,
    created_at timestamptz not null,
    updated_at timestamptz not null,
    metadata jsonb,
    constraint uniauth_credentials_type_subject_key unique (type, subject),
    constraint uniauth_credentials_type_user_key unique (type, user_id)
  )`,
  `create index if not exists uniauth_credentials_user_idx on uniauth_credentials (user_id)`,
  `create table if not exists uniauth_verifications (
    id text primary key,
    purpose text not null,
    target text not null,
    provider text,
    channel text,
    secret_hash text not null,
    status text not null check (status in ('pending', 'consumed')),
    created_at timestamptz not null,
    expires_at timestamptz not null,
    consumed_at timestamptz,
    metadata jsonb
  )`,
  `create index if not exists uniauth_verifications_target_idx on uniauth_verifications (target)`,
  `create table if not exists uniauth_sessions (
    id text primary key,
    user_id text not null references uniauth_users(id) on delete restrict,
    status text not null check (status in ('active', 'revoked', 'expired')),
    created_at timestamptz not null,
    expires_at timestamptz not null,
    revoked_at timestamptz,
    last_seen_at timestamptz,
    metadata jsonb
  )`,
  `create index if not exists uniauth_sessions_user_idx on uniauth_sessions (user_id)`,
  `create table if not exists uniauth_audit_events (
    id text primary key,
    type text not null,
    occurred_at timestamptz not null,
    user_id text,
    identity_id text,
    session_id text,
    metadata jsonb
  )`,
  `create index if not exists uniauth_audit_events_user_idx on uniauth_audit_events (user_id)`,
  `create index if not exists uniauth_audit_events_occurred_idx on uniauth_audit_events (occurred_at)`,
] as const

export const POSTGRES_AUTH_SCHEMA_SQL = `${schemaStatements.join(';\n\n')};\n`

export async function applyPostgresAuthSchema(database: PostgresQueryable): Promise<void> {
  for (const statement of schemaStatements) {
    await database.query(statement)
  }
}
