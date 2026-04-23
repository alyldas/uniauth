import { AsyncLocalStorage } from 'node:async_hooks'
import {
  asCredentialId,
  asIdentityId,
  asSessionId,
  asUserId,
  asVerificationId,
  ProviderTrustLevel,
  type AuthIdentity,
  type AuthIdentityProvider,
  type Credential,
  type CredentialType,
  type OtpChannel,
  type ProviderTrustContext,
  type Session,
  type SessionStatus,
  type User,
  type Verification,
  type VerificationPurpose,
  type VerificationStatus,
} from '../domain/types.js'
import { UniAuthError, UniAuthErrorCode } from '../errors.js'
import type {
  AuditLogRepo,
  AuthServiceRepositories,
  CredentialRepo,
  IdentityRepo,
  SessionRepo,
  UnitOfWork,
  UserRepo,
  VerificationRepo,
} from '../ports.js'
import { optionalProp } from '../utils/optional.js'
import type {
  CreatePostgresAuthStoreOptions,
  PostgresAuthStoreLike,
  PostgresPoolClient,
  PostgresQueryable,
} from './types.js'

const UniqueViolationCode = '23505'

interface UserRow {
  readonly id: string
  readonly display_name: string | null
  readonly email: string | null
  readonly phone: string | null
  readonly created_at: Date | string
  readonly updated_at: Date | string
  readonly disabled_at: Date | string | null
  readonly metadata: Record<string, unknown> | string | null
}

interface IdentityRow {
  readonly id: string
  readonly user_id: string
  readonly provider: string
  readonly provider_user_id: string
  readonly status: AuthIdentity['status']
  readonly email: string | null
  readonly email_verified: boolean | null
  readonly phone: string | null
  readonly phone_verified: boolean | null
  readonly trust: Record<string, unknown> | string | null
  readonly created_at: Date | string
  readonly updated_at: Date | string
  readonly disabled_at: Date | string | null
  readonly metadata: Record<string, unknown> | string | null
}

interface CredentialRow {
  readonly id: string
  readonly user_id: string
  readonly type: CredentialType
  readonly subject: string
  readonly password_hash: string
  readonly created_at: Date | string
  readonly updated_at: Date | string
  readonly metadata: Record<string, unknown> | string | null
}

interface VerificationRow {
  readonly id: string
  readonly purpose: VerificationPurpose
  readonly target: string
  readonly provider: string | null
  readonly channel: OtpChannel | null
  readonly secret_hash: string
  readonly status: VerificationStatus
  readonly created_at: Date | string
  readonly expires_at: Date | string
  readonly consumed_at: Date | string | null
  readonly metadata: Record<string, unknown> | string | null
}

interface SessionRow {
  readonly id: string
  readonly user_id: string
  readonly status: SessionStatus
  readonly created_at: Date | string
  readonly expires_at: Date | string
  readonly revoked_at: Date | string | null
  readonly last_seen_at: Date | string | null
  readonly metadata: Record<string, unknown> | string | null
}

interface UpdateColumn {
  readonly key: string
  readonly column: string
}

export class PostgresAuthStore
  implements PostgresAuthStoreLike, AuthServiceRepositories, UnitOfWork
{
  private readonly transactionScope = new AsyncLocalStorage<PostgresPoolClient>()

  constructor(private readonly options: CreatePostgresAuthStoreOptions) {}

  readonly userRepo: UserRepo = {
    findById: async (id) =>
      this.queryOptionalRow<UserRow, User>(
        `select id, display_name, email, phone, created_at, updated_at, disabled_at, metadata
         from uniauth_users
         where id = $1`,
        [id],
        mapUserRow,
      ),
    create: async (user) =>
      this.queryRequiredRow<UserRow, User>(
        `insert into uniauth_users (
           id, display_name, email, phone, created_at, updated_at, disabled_at, metadata
         ) values ($1, $2, $3, $4, $5, $6, $7, $8)
         returning id, display_name, email, phone, created_at, updated_at, disabled_at, metadata`,
        [
          user.id,
          user.displayName ?? null,
          user.email ?? null,
          user.phone ?? null,
          user.createdAt,
          user.updatedAt,
          user.disabledAt ?? null,
          user.metadata ?? null,
        ],
        mapUserRow,
      ),
    update: async (id, patch) => {
      const existing = await this.userRepo.findById(id)

      if (!existing) {
        throw new UniAuthError(UniAuthErrorCode.UserNotFound, 'User was not found.')
      }

      const update = buildUpdateQuery(patch, [
        { key: 'displayName', column: 'display_name' },
        { key: 'email', column: 'email' },
        { key: 'phone', column: 'phone' },
        { key: 'updatedAt', column: 'updated_at' },
        { key: 'disabledAt', column: 'disabled_at' },
        { key: 'metadata', column: 'metadata' },
      ])

      if (!update) {
        return existing
      }

      return this.queryRequiredRow<UserRow, User>(
        `update uniauth_users
         set ${update.setClause}
         where id = $${update.values.length + 1}
         returning id, display_name, email, phone, created_at, updated_at, disabled_at, metadata`,
        [...update.values, id],
        mapUserRow,
      )
    },
  }

  readonly identityRepo: IdentityRepo = {
    findById: async (id) =>
      this.queryOptionalRow<IdentityRow, AuthIdentity>(
        `select
           id, user_id, provider, provider_user_id, status, email, email_verified, phone,
           phone_verified, trust, created_at, updated_at, disabled_at, metadata
         from uniauth_identities
         where id = $1`,
        [id],
        mapIdentityRow,
      ),
    findByProviderUserId: async (provider, providerUserId) =>
      this.queryOptionalRow<IdentityRow, AuthIdentity>(
        `select
           id, user_id, provider, provider_user_id, status, email, email_verified, phone,
           phone_verified, trust, created_at, updated_at, disabled_at, metadata
         from uniauth_identities
         where provider = $1 and provider_user_id = $2`,
        [provider, providerUserId],
        mapIdentityRow,
      ),
    findByVerifiedEmail: async (email) =>
      this.queryRows<IdentityRow, AuthIdentity>(
        `select
           id, user_id, provider, provider_user_id, status, email, email_verified, phone,
           phone_verified, trust, created_at, updated_at, disabled_at, metadata
         from uniauth_identities
         where status = 'active' and email_verified = true and email = $1
         order by created_at asc, id asc`,
        [email],
        mapIdentityRow,
      ),
    findByVerifiedPhone: async (phone) =>
      this.queryRows<IdentityRow, AuthIdentity>(
        `select
           id, user_id, provider, provider_user_id, status, email, email_verified, phone,
           phone_verified, trust, created_at, updated_at, disabled_at, metadata
         from uniauth_identities
         where status = 'active' and phone_verified = true and phone = $1
         order by created_at asc, id asc`,
        [phone],
        mapIdentityRow,
      ),
    listByUserId: async (userId) =>
      this.queryRows<IdentityRow, AuthIdentity>(
        `select
           id, user_id, provider, provider_user_id, status, email, email_verified, phone,
           phone_verified, trust, created_at, updated_at, disabled_at, metadata
         from uniauth_identities
         where user_id = $1
         order by created_at asc, id asc`,
        [userId],
        mapIdentityRow,
      ),
    create: async (identity) => {
      try {
        return await this.queryRequiredRow<IdentityRow, AuthIdentity>(
          `insert into uniauth_identities (
             id, user_id, provider, provider_user_id, status, email, email_verified, phone,
             phone_verified, trust, created_at, updated_at, disabled_at, metadata
           ) values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
           returning
             id, user_id, provider, provider_user_id, status, email, email_verified, phone,
             phone_verified, trust, created_at, updated_at, disabled_at, metadata`,
          [
            identity.id,
            identity.userId,
            identity.provider,
            identity.providerUserId,
            identity.status,
            identity.email ?? null,
            identity.emailVerified ?? null,
            identity.phone ?? null,
            identity.phoneVerified ?? null,
            identity.trust ?? null,
            identity.createdAt,
            identity.updatedAt,
            identity.disabledAt ?? null,
            identity.metadata ?? null,
          ],
          mapIdentityRow,
        )
      } catch (error) {
        throw mapIdentityWriteError(error)
      }
    },
    update: async (id, patch) => {
      const existing = await this.identityRepo.findById(id)

      if (!existing) {
        throw new UniAuthError(UniAuthErrorCode.IdentityNotFound, 'Identity was not found.')
      }

      const update = buildUpdateQuery(patch, [
        { key: 'userId', column: 'user_id' },
        { key: 'provider', column: 'provider' },
        { key: 'providerUserId', column: 'provider_user_id' },
        { key: 'status', column: 'status' },
        { key: 'email', column: 'email' },
        { key: 'emailVerified', column: 'email_verified' },
        { key: 'phone', column: 'phone' },
        { key: 'phoneVerified', column: 'phone_verified' },
        { key: 'trust', column: 'trust' },
        { key: 'updatedAt', column: 'updated_at' },
        { key: 'disabledAt', column: 'disabled_at' },
        { key: 'metadata', column: 'metadata' },
      ])

      if (!update) {
        return existing
      }

      try {
        return await this.queryRequiredRow<IdentityRow, AuthIdentity>(
          `update uniauth_identities
           set ${update.setClause}
           where id = $${update.values.length + 1}
           returning
             id, user_id, provider, provider_user_id, status, email, email_verified, phone,
             phone_verified, trust, created_at, updated_at, disabled_at, metadata`,
          [...update.values, id],
          mapIdentityRow,
        )
      } catch (error) {
        throw mapIdentityWriteError(error)
      }
    },
  }

  readonly credentialRepo: CredentialRepo = {
    findPasswordByEmail: async (email) =>
      this.queryOptionalRow<CredentialRow, Credential>(
        `select
           id, user_id, type, subject, password_hash, created_at, updated_at, metadata
         from uniauth_credentials
         where type = 'password' and subject = $1`,
        [email],
        mapCredentialRow,
      ),
    findPasswordByUserId: async (userId) =>
      this.queryOptionalRow<CredentialRow, Credential>(
        `select
           id, user_id, type, subject, password_hash, created_at, updated_at, metadata
         from uniauth_credentials
         where type = 'password' and user_id = $1`,
        [userId],
        mapCredentialRow,
      ),
    create: async (credential) => {
      try {
        return await this.queryRequiredRow<CredentialRow, Credential>(
          `insert into uniauth_credentials (
             id, user_id, type, subject, password_hash, created_at, updated_at, metadata
           ) values ($1, $2, $3, $4, $5, $6, $7, $8)
           returning
             id, user_id, type, subject, password_hash, created_at, updated_at, metadata`,
          [
            credential.id,
            credential.userId,
            credential.type,
            credential.subject,
            credential.passwordHash,
            credential.createdAt,
            credential.updatedAt,
            credential.metadata ?? null,
          ],
          mapCredentialRow,
        )
      } catch (error) {
        throw mapCredentialWriteError(error)
      }
    },
    update: async (id, patch) => {
      const existing = await this.queryOptionalRow<CredentialRow, Credential>(
        `select
           id, user_id, type, subject, password_hash, created_at, updated_at, metadata
         from uniauth_credentials
         where id = $1`,
        [id],
        mapCredentialRow,
      )

      if (!existing) {
        throw new UniAuthError(UniAuthErrorCode.CredentialNotFound, 'Credential was not found.')
      }

      const update = buildUpdateQuery(patch, [
        { key: 'subject', column: 'subject' },
        { key: 'passwordHash', column: 'password_hash' },
        { key: 'updatedAt', column: 'updated_at' },
        { key: 'metadata', column: 'metadata' },
      ])

      if (!update) {
        return existing
      }

      try {
        return await this.queryRequiredRow<CredentialRow, Credential>(
          `update uniauth_credentials
           set ${update.setClause}
           where id = $${update.values.length + 1}
           returning
             id, user_id, type, subject, password_hash, created_at, updated_at, metadata`,
          [...update.values, id],
          mapCredentialRow,
        )
      } catch (error) {
        throw mapCredentialWriteError(error)
      }
    },
  }

  readonly verificationRepo: VerificationRepo = {
    findById: async (id) =>
      this.queryOptionalRow<VerificationRow, Verification>(
        `select
           id, purpose, target, provider, channel, secret_hash, status, created_at, expires_at,
           consumed_at, metadata
         from uniauth_verifications
         where id = $1`,
        [id],
        mapVerificationRow,
      ),
    create: async (verification) =>
      this.queryRequiredRow<VerificationRow, Verification>(
        `insert into uniauth_verifications (
           id, purpose, target, provider, channel, secret_hash, status, created_at, expires_at,
           consumed_at, metadata
         ) values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
         returning
           id, purpose, target, provider, channel, secret_hash, status, created_at, expires_at,
           consumed_at, metadata`,
        [
          verification.id,
          verification.purpose,
          verification.target,
          verification.provider ?? null,
          verification.channel ?? null,
          verification.secretHash,
          verification.status,
          verification.createdAt,
          verification.expiresAt,
          verification.consumedAt ?? null,
          verification.metadata ?? null,
        ],
        mapVerificationRow,
      ),
    update: async (id, patch) => {
      const existing = await this.verificationRepo.findById(id)

      if (!existing) {
        throw new UniAuthError(UniAuthErrorCode.VerificationNotFound, 'Verification was not found.')
      }

      const update = buildUpdateQuery(patch, [
        { key: 'purpose', column: 'purpose' },
        { key: 'target', column: 'target' },
        { key: 'provider', column: 'provider' },
        { key: 'channel', column: 'channel' },
        { key: 'secretHash', column: 'secret_hash' },
        { key: 'status', column: 'status' },
        { key: 'expiresAt', column: 'expires_at' },
        { key: 'consumedAt', column: 'consumed_at' },
        { key: 'metadata', column: 'metadata' },
      ])

      if (!update) {
        return existing
      }

      return this.queryRequiredRow<VerificationRow, Verification>(
        `update uniauth_verifications
         set ${update.setClause}
         where id = $${update.values.length + 1}
         returning
           id, purpose, target, provider, channel, secret_hash, status, created_at, expires_at,
           consumed_at, metadata`,
        [...update.values, id],
        mapVerificationRow,
      )
    },
  }

  readonly sessionRepo: SessionRepo = {
    findById: async (id) =>
      this.queryOptionalRow<SessionRow, Session>(
        `select
           id, user_id, status, created_at, expires_at, revoked_at, last_seen_at, metadata
         from uniauth_sessions
         where id = $1`,
        [id],
        mapSessionRow,
      ),
    listByUserId: async (userId) =>
      this.queryRows<SessionRow, Session>(
        `select
           id, user_id, status, created_at, expires_at, revoked_at, last_seen_at, metadata
         from uniauth_sessions
         where user_id = $1
         order by created_at asc, id asc`,
        [userId],
        mapSessionRow,
      ),
    create: async (session) =>
      this.queryRequiredRow<SessionRow, Session>(
        `insert into uniauth_sessions (
           id, user_id, status, created_at, expires_at, revoked_at, last_seen_at, metadata
         ) values ($1, $2, $3, $4, $5, $6, $7, $8)
         returning
           id, user_id, status, created_at, expires_at, revoked_at, last_seen_at, metadata`,
        [
          session.id,
          session.userId,
          session.status,
          session.createdAt,
          session.expiresAt,
          session.revokedAt ?? null,
          session.lastSeenAt ?? null,
          session.metadata ?? null,
        ],
        mapSessionRow,
      ),
    update: async (id, patch) => {
      const existing = await this.sessionRepo.findById(id)

      if (!existing) {
        throw new UniAuthError(UniAuthErrorCode.SessionNotFound, 'Session was not found.')
      }

      const update = buildUpdateQuery(patch, [
        { key: 'userId', column: 'user_id' },
        { key: 'status', column: 'status' },
        { key: 'expiresAt', column: 'expires_at' },
        { key: 'revokedAt', column: 'revoked_at' },
        { key: 'lastSeenAt', column: 'last_seen_at' },
        { key: 'metadata', column: 'metadata' },
      ])

      if (!update) {
        return existing
      }

      return this.queryRequiredRow<SessionRow, Session>(
        `update uniauth_sessions
         set ${update.setClause}
         where id = $${update.values.length + 1}
         returning
           id, user_id, status, created_at, expires_at, revoked_at, last_seen_at, metadata`,
        [...update.values, id],
        mapSessionRow,
      )
    },
  }

  readonly auditLogRepo: AuditLogRepo = {
    append: async (event) => {
      await this.query(
        `insert into uniauth_audit_events (
           id, type, occurred_at, user_id, identity_id, session_id, metadata
         ) values ($1, $2, $3, $4, $5, $6, $7)`,
        [
          event.id,
          event.type,
          event.occurredAt,
          event.userId ?? null,
          event.identityId ?? null,
          event.sessionId ?? null,
          event.metadata ?? null,
        ],
      )
    },
  }

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

function mapUserRow(row: UserRow): User {
  return {
    id: asUserId(row.id),
    createdAt: readDate(row.created_at),
    updatedAt: readDate(row.updated_at),
    ...optionalProp('displayName', readString(row.display_name)),
    ...optionalProp('email', readString(row.email)),
    ...optionalProp('phone', readString(row.phone)),
    ...optionalProp('disabledAt', readOptionalDate(row.disabled_at)),
    ...optionalProp('metadata', readJsonObject(row.metadata)),
  }
}

function mapIdentityRow(row: IdentityRow): AuthIdentity {
  return {
    id: asIdentityId(row.id),
    userId: asUserId(row.user_id),
    provider: row.provider,
    providerUserId: row.provider_user_id,
    status: row.status,
    createdAt: readDate(row.created_at),
    updatedAt: readDate(row.updated_at),
    ...optionalProp('email', readString(row.email)),
    ...(row.email_verified !== null ? { emailVerified: row.email_verified } : {}),
    ...optionalProp('phone', readString(row.phone)),
    ...(row.phone_verified !== null ? { phoneVerified: row.phone_verified } : {}),
    ...optionalProp('trust', readProviderTrust(row.trust)),
    ...optionalProp('disabledAt', readOptionalDate(row.disabled_at)),
    ...optionalProp('metadata', readJsonObject(row.metadata)),
  }
}

function mapCredentialRow(row: CredentialRow): Credential {
  return {
    id: asCredentialId(row.id),
    userId: asUserId(row.user_id),
    type: row.type,
    subject: row.subject,
    passwordHash: row.password_hash,
    createdAt: readDate(row.created_at),
    updatedAt: readDate(row.updated_at),
    ...optionalProp('metadata', readJsonObject(row.metadata)),
  }
}

function mapVerificationRow(row: VerificationRow): Verification {
  return {
    id: asVerificationId(row.id),
    purpose: row.purpose,
    target: row.target,
    secretHash: row.secret_hash,
    status: row.status,
    createdAt: readDate(row.created_at),
    expiresAt: readDate(row.expires_at),
    ...optionalProp('provider', readString(row.provider) as AuthIdentityProvider | undefined),
    ...optionalProp('channel', row.channel ?? undefined),
    ...optionalProp('consumedAt', readOptionalDate(row.consumed_at)),
    ...optionalProp('metadata', readJsonObject(row.metadata)),
  }
}

function mapSessionRow(row: SessionRow): Session {
  return {
    id: asSessionId(row.id),
    userId: asUserId(row.user_id),
    status: row.status,
    createdAt: readDate(row.created_at),
    expiresAt: readDate(row.expires_at),
    ...optionalProp('revokedAt', readOptionalDate(row.revoked_at)),
    ...optionalProp('lastSeenAt', readOptionalDate(row.last_seen_at)),
    ...optionalProp('metadata', readJsonObject(row.metadata)),
  }
}

function buildUpdateQuery(
  patch: Record<string, unknown>,
  columns: readonly UpdateColumn[],
): { readonly setClause: string; readonly values: readonly unknown[] } | undefined {
  const assignments: string[] = []
  const values: unknown[] = []

  for (const column of columns) {
    if (!Object.prototype.hasOwnProperty.call(patch, column.key)) {
      continue
    }

    assignments.push(`${column.column} = $${values.length + 1}`)
    values.push(patch[column.key] ?? null)
  }

  if (assignments.length === 0) {
    return undefined
  }

  return {
    setClause: assignments.join(', '),
    values,
  }
}

function mapIdentityWriteError(error: unknown): Error {
  if (isUniqueViolation(error)) {
    return new UniAuthError(UniAuthErrorCode.IdentityAlreadyLinked, 'Identity cannot be linked.')
  }

  return toError(error)
}

function mapCredentialWriteError(error: unknown): Error {
  if (isUniqueViolation(error)) {
    return new UniAuthError(UniAuthErrorCode.CredentialAlreadyExists, 'Credential already exists.')
  }

  return toError(error)
}

function isUniqueViolation(error: unknown): boolean {
  return typeof error === 'object' && error !== null && 'code' in error
    ? (error as { code?: unknown }).code === UniqueViolationCode
    : false
}

function readDate(value: Date | string): Date {
  if (value instanceof Date) {
    return value
  }

  const parsed = new Date(value)

  if (Number.isNaN(parsed.getTime())) {
    throw new Error('Invalid date value returned from Postgres.')
  }

  return parsed
}

function readOptionalDate(value: Date | string | null): Date | undefined {
  return value === null ? undefined : readDate(value)
}

function readString(value: string | null): string | undefined {
  return value ?? undefined
}

function readJsonObject(
  value: Record<string, unknown> | string | null,
): Record<string, unknown> | undefined {
  if (value === null) {
    return undefined
  }

  if (typeof value === 'string') {
    const parsed = JSON.parse(value) as unknown
    return ensureRecord(parsed)
  }

  return ensureRecord(value)
}

function readProviderTrust(
  value: Record<string, unknown> | string | null,
): ProviderTrustContext | undefined {
  const record = readJsonObject(value)

  if (!record) {
    return undefined
  }

  const level = readTrustLevel(record.level)

  if (!level) {
    throw new Error('Invalid provider trust payload returned from Postgres.')
  }

  const signals = readTrustSignals(record.signals)

  return {
    level,
    ...optionalProp('signals', signals),
    ...optionalProp('metadata', readNestedRecord(record.metadata)),
  }
}

function readTrustLevel(value: unknown): ProviderTrustLevel | undefined {
  if (value === ProviderTrustLevel.Trusted) {
    return ProviderTrustLevel.Trusted
  }

  if (value === ProviderTrustLevel.Neutral) {
    return ProviderTrustLevel.Neutral
  }

  if (value === ProviderTrustLevel.Untrusted) {
    return ProviderTrustLevel.Untrusted
  }

  return undefined
}

function readTrustSignals(value: unknown): readonly string[] | undefined {
  if (value === undefined) {
    return undefined
  }

  if (!Array.isArray(value) || value.some((entry) => typeof entry !== 'string')) {
    throw new Error('Invalid provider trust signals returned from Postgres.')
  }

  return value.length > 0
    ? [...new Set(value.map((entry) => entry.trim()).filter(Boolean))]
    : undefined
}

function readNestedRecord(value: unknown): Record<string, unknown> | undefined {
  if (value === undefined || value === null) {
    return undefined
  }

  return ensureRecord(value)
}

function ensureRecord(value: unknown): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new Error('Expected a JSON object returned from Postgres.')
  }

  return value as Record<string, unknown>
}

function toError(error: unknown): Error {
  return error instanceof Error ? error : new Error('Unknown Postgres error.')
}
