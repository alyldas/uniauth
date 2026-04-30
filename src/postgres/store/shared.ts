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
} from '../../domain/types.js'
import { UniAuthError, UniAuthErrorCode } from '../../errors.js'
import { optionalProp } from '../../utils/optional.js'

const UniqueViolationCode = '23505'

export interface UserRow {
  readonly id: string
  readonly display_name: string | null
  readonly email: string | null
  readonly phone: string | null
  readonly created_at: Date | string
  readonly updated_at: Date | string
  readonly disabled_at: Date | string | null
  readonly metadata: Record<string, unknown> | string | null
}

export interface IdentityRow {
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

export interface CredentialRow {
  readonly id: string
  readonly user_id: string
  readonly type: CredentialType
  readonly subject: string
  readonly password_hash: string
  readonly created_at: Date | string
  readonly updated_at: Date | string
  readonly metadata: Record<string, unknown> | string | null
}

export interface VerificationRow {
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

export interface SessionRow {
  readonly id: string
  readonly user_id: string
  readonly token_hash: string
  readonly status: SessionStatus
  readonly created_at: Date | string
  readonly expires_at: Date | string
  readonly revoked_at: Date | string | null
  readonly last_seen_at: Date | string | null
  readonly metadata: Record<string, unknown> | string | null
}

export interface UpdateColumn {
  readonly key: string
  readonly column: string
}

export interface PostgresStoreContext {
  query(text: string, values?: readonly unknown[]): Promise<void>
  queryOptionalRow<Row extends object, Result>(
    text: string,
    values: readonly unknown[],
    mapRow: (row: Row) => Result,
  ): Promise<Result | undefined>
  queryRequiredRow<Row extends object, Result>(
    text: string,
    values: readonly unknown[],
    mapRow: (row: Row) => Result,
  ): Promise<Result>
  queryRows<Row extends object, Result>(
    text: string,
    values: readonly unknown[],
    mapRow: (row: Row) => Result,
  ): Promise<readonly Result[]>
}

export function mapUserRow(row: UserRow): User {
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

export function mapIdentityRow(row: IdentityRow): AuthIdentity {
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

export function mapCredentialRow(row: CredentialRow): Credential {
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

export function mapVerificationRow(row: VerificationRow): Verification {
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

export function mapSessionRow(row: SessionRow): Session {
  return {
    id: asSessionId(row.id),
    userId: asUserId(row.user_id),
    tokenHash: row.token_hash,
    status: row.status,
    createdAt: readDate(row.created_at),
    expiresAt: readDate(row.expires_at),
    ...optionalProp('revokedAt', readOptionalDate(row.revoked_at)),
    ...optionalProp('lastSeenAt', readOptionalDate(row.last_seen_at)),
    ...optionalProp('metadata', readJsonObject(row.metadata)),
  }
}

export function buildUpdateQuery(
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

export function mapIdentityWriteError(error: unknown): Error {
  if (isUniqueViolation(error)) {
    return new UniAuthError(UniAuthErrorCode.IdentityAlreadyLinked, 'Identity cannot be linked.')
  }

  return toError(error)
}

export function mapCredentialWriteError(error: unknown): Error {
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
