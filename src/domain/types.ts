declare const brand: unique symbol

export type Brand<Value, Name extends string> = Value & { readonly [brand]: Name }

export type UserId = Brand<string, 'UserId'>
export type IdentityId = Brand<string, 'IdentityId'>
export type CredentialId = Brand<string, 'CredentialId'>
export type VerificationId = Brand<string, 'VerificationId'>
export type SessionId = Brand<string, 'SessionId'>
export type AuditEventId = Brand<string, 'AuditEventId'>

export type AuthIdentityProvider = string

export const EMAIL_OTP_PROVIDER_ID = 'email-otp'
export const EMAIL_MAGIC_LINK_PROVIDER_ID = 'email-magic-link'
export const PHONE_OTP_PROVIDER_ID = 'phone-otp'
export const PASSWORD_PROVIDER_ID = 'password'

export type ExtensibleString<Literal extends string> = Literal | (string & Record<never, never>)

export const AuthIdentityStatus = {
  Active: 'active',
  Disabled: 'disabled',
} as const

export type AuthIdentityStatus = (typeof AuthIdentityStatus)[keyof typeof AuthIdentityStatus]

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

export const OtpChannel = {
  Email: 'email',
  Phone: 'phone',
} as const

export type OtpChannel = (typeof OtpChannel)[keyof typeof OtpChannel]

export const CredentialType = {
  Password: 'password',
} as const

export type CredentialType = (typeof CredentialType)[keyof typeof CredentialType]

export const SessionStatus = {
  Active: 'active',
  Revoked: 'revoked',
  Expired: 'expired',
} as const

export type SessionStatus = (typeof SessionStatus)[keyof typeof SessionStatus]

export const ProviderTrustLevel = {
  Trusted: 'trusted',
  Neutral: 'neutral',
  Untrusted: 'untrusted',
} as const

export type ProviderTrustLevel = (typeof ProviderTrustLevel)[keyof typeof ProviderTrustLevel]

export interface ProviderTrustContext {
  readonly level: ProviderTrustLevel
  readonly signals?: readonly string[]
  readonly metadata?: Record<string, unknown>
}

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
  readonly trust?: ProviderTrustContext
  readonly createdAt: Date
  readonly updatedAt: Date
  readonly disabledAt?: Date
  readonly metadata?: Record<string, unknown>
}

export interface Verification {
  readonly id: VerificationId
  readonly purpose: VerificationPurpose
  readonly target: string
  readonly provider?: AuthIdentityProvider
  readonly channel?: OtpChannel
  readonly secretHash: string
  readonly status: VerificationStatus
  readonly createdAt: Date
  readonly expiresAt: Date
  readonly consumedAt?: Date
  readonly metadata?: Record<string, unknown>
}

export interface Credential {
  readonly id: CredentialId
  readonly userId: UserId
  readonly type: CredentialType
  readonly subject: string
  readonly passwordHash: string
  readonly createdAt: Date
  readonly updatedAt: Date
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
  readonly trust?: ProviderTrustContext
  readonly metadata?: Record<string, unknown>
}

export interface FinishInput {
  readonly code?: string
  readonly state?: string
  readonly payload?: unknown
  readonly metadata?: Record<string, unknown>
}

export const AuditEventType = {
  SignIn: 'auth.sign_in',
  IdentityLinked: 'auth.identity_linked',
  IdentityUnlinked: 'auth.identity_unlinked',
  AccountsMerged: 'auth.accounts_merged',
  SessionCreated: 'auth.session_created',
  SessionRevoked: 'auth.session_revoked',
  VerificationCreated: 'auth.verification_created',
  VerificationConsumed: 'auth.verification_consumed',
  PolicyDenied: 'auth.policy_denied',
  RateLimited: 'auth.rate_limited',
} as const

export type AuditEventType = (typeof AuditEventType)[keyof typeof AuditEventType]

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
  readonly movedCredentialIds: readonly CredentialId[]
  readonly revokedSessionIds: readonly SessionId[]
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

export interface StartOtpChallengeInput {
  readonly purpose: VerificationPurpose
  readonly channel: OtpChannel
  readonly target: string
  readonly secret?: string
  readonly ttlSeconds?: number
  readonly now?: Date
  readonly metadata?: Record<string, unknown>
}

export interface StartOtpChallengeResult {
  readonly verificationId: VerificationId
  readonly expiresAt: Date
  readonly delivery: OtpChannel
}

export interface FinishOtpChallengeInput {
  readonly verificationId: VerificationId
  readonly secret: string
  readonly purpose?: VerificationPurpose
  readonly channel?: OtpChannel
  readonly now?: Date
}

export interface FinishOtpSignInInput {
  readonly verificationId: VerificationId
  readonly secret: string
  readonly channel?: OtpChannel
  readonly now?: Date
  readonly sessionExpiresAt?: Date
  readonly metadata?: Record<string, unknown>
}

export interface EmailMagicLink {
  readonly verificationId: VerificationId
  readonly secret: string
  readonly email: string
  readonly expiresAt: Date
}

export interface StartEmailMagicLinkSignInInput {
  readonly email: string
  readonly createLink: (input: EmailMagicLink) => string | Promise<string>
  readonly secret?: string
  readonly ttlSeconds?: number
  readonly now?: Date
  readonly metadata?: Record<string, unknown>
}

export interface StartEmailMagicLinkSignInResult {
  readonly verificationId: VerificationId
  readonly expiresAt: Date
  readonly delivery: typeof OtpChannel.Email
}

export interface FinishEmailMagicLinkSignInInput {
  readonly verificationId: VerificationId
  readonly secret: string
  readonly now?: Date
  readonly sessionExpiresAt?: Date
  readonly metadata?: Record<string, unknown>
}

export interface SignInWithPasswordInput {
  readonly email: string
  readonly password: string
  readonly now?: Date
  readonly sessionExpiresAt?: Date
  readonly metadata?: Record<string, unknown>
}

export interface SetPasswordInput {
  readonly userId: UserId
  readonly email: string
  readonly password: string
  readonly reAuthenticatedAt?: Date
  readonly now?: Date
  readonly metadata?: Record<string, unknown>
}

export interface ChangePasswordInput {
  readonly userId: UserId
  readonly currentPassword: string
  readonly newPassword: string
  readonly reAuthenticatedAt?: Date
  readonly now?: Date
  readonly metadata?: Record<string, unknown>
}

export interface EmailPasswordRecoveryLink {
  readonly verificationId: VerificationId
  readonly secret: string
  readonly email: string
  readonly expiresAt: Date
}

export interface StartEmailPasswordRecoveryInput {
  readonly email: string
  readonly createLink: (input: EmailPasswordRecoveryLink) => string | Promise<string>
  readonly secret?: string
  readonly ttlSeconds?: number
  readonly now?: Date
  readonly metadata?: Record<string, unknown>
}

export interface StartEmailPasswordRecoveryResult {
  readonly verificationId: VerificationId
  readonly expiresAt: Date
  readonly delivery: typeof OtpChannel.Email
}

export interface FinishEmailPasswordRecoveryInput {
  readonly verificationId: VerificationId
  readonly secret: string
  readonly newPassword: string
  readonly now?: Date
  readonly metadata?: Record<string, unknown>
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
  signInWithPassword(input: SignInWithPasswordInput): Promise<AuthResult>
  startOtpChallenge(input: StartOtpChallengeInput): Promise<StartOtpChallengeResult>
  finishOtpChallenge(input: FinishOtpChallengeInput): Promise<Verification>
  finishOtpSignIn(input: FinishOtpSignInInput): Promise<AuthResult>
  startEmailMagicLinkSignIn(
    input: StartEmailMagicLinkSignInInput,
  ): Promise<StartEmailMagicLinkSignInResult>
  finishEmailMagicLinkSignIn(input: FinishEmailMagicLinkSignInInput): Promise<AuthResult>
  setPassword(input: SetPasswordInput): Promise<Credential>
  changePassword(input: ChangePasswordInput): Promise<Credential>
  startEmailPasswordRecovery(
    input: StartEmailPasswordRecoveryInput,
  ): Promise<StartEmailPasswordRecoveryResult>
  finishEmailPasswordRecovery(input: FinishEmailPasswordRecoveryInput): Promise<Credential>
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
