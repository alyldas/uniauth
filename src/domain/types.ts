declare const brand: unique symbol

export type Brand<Value, Name extends string> = Value & { readonly [brand]: Name }

export type UserId = Brand<string, 'UserId'>
export type IdentityId = Brand<string, 'IdentityId'>
export type CredentialId = Brand<string, 'CredentialId'>
export type VerificationId = Brand<string, 'VerificationId'>
export type SessionId = Brand<string, 'SessionId'>
export type AuditEventId = Brand<string, 'AuditEventId'>

export type AuthIdentityProvider = string

export type ExtensibleString<Literal extends string> = Literal | (string & Record<never, never>)

export const AuthIdentityStatus = {
  Active: 'active',
  Disabled: 'disabled',
} as const

export type AuthIdentityStatus = (typeof AuthIdentityStatus)[keyof typeof AuthIdentityStatus]

export const CredentialType = {
  Password: 'password',
  Passkey: 'passkey',
  ProviderSecret: 'provider-secret',
} as const

export type CredentialType = ExtensibleString<(typeof CredentialType)[keyof typeof CredentialType]>

export const VerificationPurpose = {
  SignIn: 'sign-in',
  Link: 'link',
  ReAuth: 're-auth',
  Recovery: 'recovery',
} as const

export type VerificationPurpose = ExtensibleString<
  (typeof VerificationPurpose)[keyof typeof VerificationPurpose]
>

export const VerificationStatus = {
  Pending: 'pending',
  Consumed: 'consumed',
} as const

export type VerificationStatus = (typeof VerificationStatus)[keyof typeof VerificationStatus]

export const SessionStatus = {
  Active: 'active',
  Revoked: 'revoked',
  Expired: 'expired',
} as const

export type SessionStatus = (typeof SessionStatus)[keyof typeof SessionStatus]

export interface User {
  readonly id: UserId
  readonly displayName?: string
  readonly email?: string
  readonly phone?: string
  readonly createdAt: Date
  readonly updatedAt: Date
  readonly disabledAt?: Date
  readonly metadata?: Record<string, unknown>
}

export interface AuthIdentity {
  readonly id: IdentityId
  readonly userId: UserId
  readonly provider: AuthIdentityProvider
  readonly providerUserId: string
  readonly status: AuthIdentityStatus
  readonly email?: string
  readonly emailVerified?: boolean
  readonly phone?: string
  readonly phoneVerified?: boolean
  readonly createdAt: Date
  readonly updatedAt: Date
  readonly disabledAt?: Date
  readonly metadata?: Record<string, unknown>
}

export interface Credential {
  readonly id: CredentialId
  readonly userId: UserId
  readonly identityId?: IdentityId
  readonly type: CredentialType
  readonly secretHash: string
  readonly createdAt: Date
  readonly updatedAt: Date
  readonly disabledAt?: Date
  readonly metadata?: Record<string, unknown>
}

export interface Verification {
  readonly id: VerificationId
  readonly purpose: VerificationPurpose
  readonly target: string
  readonly secretHash: string
  readonly status: VerificationStatus
  readonly createdAt: Date
  readonly expiresAt: Date
  readonly consumedAt?: Date
  readonly metadata?: Record<string, unknown>
}

export interface Session {
  readonly id: SessionId
  readonly userId: UserId
  readonly status: SessionStatus
  readonly createdAt: Date
  readonly expiresAt: Date
  readonly revokedAt?: Date
  readonly lastSeenAt?: Date
  readonly metadata?: Record<string, unknown>
}

export interface ProviderIdentityAssertion {
  readonly provider: AuthIdentityProvider
  readonly providerUserId: string
  readonly email?: string
  readonly emailVerified?: boolean
  readonly phone?: string
  readonly phoneVerified?: boolean
  readonly displayName?: string
  readonly metadata?: Record<string, unknown>
  readonly rawProfile?: unknown
}

export interface StartInput {
  readonly redirectUrl?: string
  readonly state?: string
  readonly metadata?: Record<string, unknown>
}

export interface StartResult {
  readonly kind: 'redirect' | 'challenge' | 'noop'
  readonly url?: string
  readonly challengeId?: string
  readonly metadata?: Record<string, unknown>
}

export interface FinishInput {
  readonly code?: string
  readonly state?: string
  readonly payload?: unknown
  readonly metadata?: Record<string, unknown>
}

export type AuditEventType =
  | 'auth.sign_in'
  | 'auth.identity_linked'
  | 'auth.identity_unlinked'
  | 'auth.accounts_merged'
  | 'auth.session_created'
  | 'auth.session_revoked'
  | 'auth.verification_created'
  | 'auth.verification_consumed'
  | 'auth.policy_denied'

export interface AuditEvent {
  readonly id: AuditEventId
  readonly type: AuditEventType
  readonly occurredAt: Date
  readonly userId?: UserId
  readonly identityId?: IdentityId
  readonly sessionId?: SessionId
  readonly metadata?: Record<string, unknown>
}

export interface SignInInput {
  readonly assertion?: ProviderIdentityAssertion
  readonly provider?: AuthIdentityProvider
  readonly finishInput?: FinishInput
  readonly now?: Date
  readonly sessionExpiresAt?: Date
  readonly metadata?: Record<string, unknown>
}

export interface AuthResult {
  readonly user: User
  readonly identity: AuthIdentity
  readonly session: Session
  readonly isNewUser: boolean
  readonly isNewIdentity: boolean
}

export interface LinkInput {
  readonly userId: UserId
  readonly assertion?: ProviderIdentityAssertion
  readonly provider?: AuthIdentityProvider
  readonly finishInput?: FinishInput
  readonly reAuthenticatedAt?: Date
  readonly now?: Date
  readonly metadata?: Record<string, unknown>
}

export interface LinkResult {
  readonly user: User
  readonly identity: AuthIdentity
  readonly linked: boolean
}

export interface UnlinkInput {
  readonly userId: UserId
  readonly identityId: IdentityId
  readonly reAuthenticatedAt?: Date
  readonly now?: Date
  readonly metadata?: Record<string, unknown>
}

export interface MergeAccountsInput {
  readonly sourceUserId: UserId
  readonly targetUserId: UserId
  readonly reAuthenticatedAt?: Date
  readonly now?: Date
  readonly metadata?: Record<string, unknown>
}

export interface MergeResult {
  readonly sourceUser: User
  readonly targetUser: User
  readonly movedIdentityIds: readonly IdentityId[]
}

export interface CreateSessionInput {
  readonly userId: UserId
  readonly expiresAt?: Date
  readonly now?: Date
  readonly metadata?: Record<string, unknown>
}

export interface CreateVerificationInput {
  readonly purpose: VerificationPurpose
  readonly target: string
  readonly secret?: string
  readonly ttlSeconds?: number
  readonly now?: Date
  readonly metadata?: Record<string, unknown>
}

export interface CreateVerificationResult {
  readonly verification: Verification
  readonly secret: string
}

export interface ConsumeVerificationInput {
  readonly verificationId: VerificationId
  readonly secret: string
  readonly now?: Date
}

export interface Clock {
  now(): Date
}

export interface IdGenerator {
  userId(): UserId
  identityId(): IdentityId
  credentialId(): CredentialId
  verificationId(): VerificationId
  sessionId(): SessionId
  auditEventId(): AuditEventId
}

export interface AuthService {
  signIn(input: SignInInput): Promise<AuthResult>
  link(input: LinkInput): Promise<LinkResult>
  unlink(input: UnlinkInput): Promise<void>
  mergeAccounts(input: MergeAccountsInput): Promise<MergeResult>
  revokeSession(sessionId: SessionId): Promise<void>
  getUserIdentities(userId: UserId): Promise<readonly AuthIdentity[]>
  createSession(input: CreateSessionInput): Promise<Session>
  createVerification(input: CreateVerificationInput): Promise<CreateVerificationResult>
  consumeVerification(input: ConsumeVerificationInput): Promise<Verification>
}

export function asUserId(value: string): UserId {
  return value as UserId
}

export function asIdentityId(value: string): IdentityId {
  return value as IdentityId
}

export function asCredentialId(value: string): CredentialId {
  return value as CredentialId
}

export function asVerificationId(value: string): VerificationId {
  return value as VerificationId
}

export function asSessionId(value: string): SessionId {
  return value as SessionId
}

export function asAuditEventId(value: string): AuditEventId {
  return value as AuditEventId
}
