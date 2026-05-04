import type {
  AuthIdentity,
  ProviderIdentityAssertion,
  Session,
  User,
  Verification,
} from './entities.js'
import type { AuditEventQuery } from './audit.js'
import type { CredentialId, IdentityId, SessionId, UserId, VerificationId } from './ids.js'
import type { OtpChannel, VerificationPurpose } from './kinds.js'
import type { AuthPolicyAction } from './policy.js'
import type { AuthIdentityProvider, FinishInput } from './providers.js'

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
  readonly sessionToken: string
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

export interface UnlinkCurrentIdentityByTokenInput {
  readonly sessionToken: string
  readonly identityId: IdentityId
  readonly reAuthenticatedAt?: Date
  readonly now?: Date
  readonly metadata?: Record<string, unknown>
}

export interface LinkCurrentIdentityByTokenInput {
  readonly sessionToken: string
  readonly assertion?: ProviderIdentityAssertion
  readonly provider?: AuthIdentityProvider
  readonly finishInput?: FinishInput
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

export interface CreateSessionResult {
  readonly session: Session
  readonly sessionToken: string
}

export interface ResolveSessionInput {
  readonly sessionToken: string
  readonly now?: Date
}

export interface TouchSessionInput {
  readonly sessionId: SessionId
  readonly now?: Date
}

export interface ResolveSessionContextInput {
  readonly sessionToken: string
  readonly touch?: boolean
  readonly now?: Date
}

export interface ResolvedSessionContext {
  readonly session: Session
  readonly user: User
}

export interface GetCurrentAccountSecuritySnapshotInput {
  readonly sessionToken: string
  readonly touch?: boolean
  readonly now?: Date
}

export interface CurrentAccountAuditWindow {
  readonly identityId?: AuditEventQuery['identityId']
  readonly sessionId?: AuditEventQuery['sessionId']
  readonly type?: AuditEventQuery['type']
  readonly before?: AuditEventQuery['before']
  readonly after?: AuditEventQuery['after']
  readonly limit?: AuditEventQuery['limit']
}

export interface GetCurrentAccountInspectionSnapshotInput {
  readonly sessionToken: string
  readonly touch?: boolean
  readonly now?: Date
  readonly auditLimit?: number
  readonly audit?: CurrentAccountAuditWindow
}

export interface GetCurrentAccountAuditEventPageInput {
  readonly sessionToken: string
  readonly touch?: boolean
  readonly now?: Date
  readonly identityId?: AuditEventQuery['identityId']
  readonly sessionId?: AuditEventQuery['sessionId']
  readonly type?: AuditEventQuery['type']
  readonly before?: AuditEventQuery['before']
  readonly after?: AuditEventQuery['after']
  readonly limit?: AuditEventQuery['limit']
}

export interface StartCurrentAccountOtpReAuthInput {
  readonly sessionToken: string
  readonly identityId: IdentityId
  readonly channel: OtpChannel
  readonly secret?: string
  readonly ttlSeconds?: number
  readonly now?: Date
  readonly metadata?: Record<string, unknown>
}

export interface ResendCurrentAccountOtpReAuthInput {
  readonly sessionToken: string
  readonly verificationId: VerificationId
  readonly secret?: string
  readonly ttlSeconds?: number
  readonly now?: Date
  readonly metadata?: Record<string, unknown>
}

export interface CancelCurrentAccountOtpReAuthInput {
  readonly sessionToken: string
  readonly verificationId: VerificationId
  readonly now?: Date
  readonly metadata?: Record<string, unknown>
}

export interface GetCurrentAccountReAuthStatusInput {
  readonly sessionToken: string
  readonly action: AuthPolicyAction
  readonly reAuthenticatedAt?: Date
  readonly now?: Date
}

export interface CurrentAccountReAuthStatus {
  readonly currentSessionId: SessionId
  readonly userId: UserId
  readonly action: AuthPolicyAction
  readonly required: boolean
  readonly checkedAt: Date
  readonly reAuthenticatedAt?: Date
}

export interface AssertCurrentAccountReAuthInput {
  readonly sessionToken: string
  readonly action: AuthPolicyAction
  readonly reAuthenticatedAt?: Date
  readonly now?: Date
}

export interface CurrentAccountReAuthAssertion {
  readonly currentSessionId: SessionId
  readonly userId: UserId
  readonly action: AuthPolicyAction
  readonly checkedAt: Date
  readonly reAuthenticatedAt?: Date
}

export interface RevokeCurrentSessionByTokenInput {
  readonly sessionToken: string
  readonly now?: Date
}

export interface RevokeOwnedSessionByTokenInput {
  readonly sessionToken: string
  readonly targetSessionId: SessionId
  readonly now?: Date
}

export interface RevokeOwnedSessionByTokenResult {
  readonly currentSessionId: SessionId
  readonly revokedSessionId: SessionId
  readonly revokedCurrentSession: boolean
}

export interface RevokeOtherSessionsByTokenInput {
  readonly sessionToken: string
  readonly now?: Date
}

export interface RevokeOtherSessionsByTokenResult extends RevokeUserSessionsResult {
  readonly currentSessionId: SessionId
}

export interface RevokeUserSessionsInput {
  readonly userId: UserId
  readonly exceptSessionId?: SessionId
  readonly now?: Date
}

export interface RevokeUserSessionsResult {
  readonly userId: UserId
  readonly revokedSessionIds: readonly SessionId[]
}

export interface AccountInspectionAuditWindow {
  readonly before?: AuditEventQuery['before']
  readonly after?: AuditEventQuery['after']
  readonly limit?: AuditEventQuery['limit']
}

export interface GetAccountInspectionSnapshotInput {
  readonly userId: UserId
  readonly auditLimit?: number
  readonly audit?: AccountInspectionAuditWindow
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

export interface CancelVerificationInput {
  readonly verificationId: VerificationId
  readonly now?: Date
  readonly metadata?: Record<string, unknown>
}

export interface GetVerificationResendWindowInput {
  readonly verificationId: VerificationId
  readonly cooldownSeconds?: number
  readonly now?: Date
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

export interface ResendOtpChallengeInput {
  readonly verificationId: VerificationId
  readonly secret?: string
  readonly ttlSeconds?: number
  readonly now?: Date
  readonly metadata?: Record<string, unknown>
}

export interface CancelOtpChallengeInput {
  readonly verificationId: VerificationId
  readonly purpose?: VerificationPurpose
  readonly channel?: OtpChannel
  readonly now?: Date
  readonly metadata?: Record<string, unknown>
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
