import type {
  AuthIdentity,
  ProviderIdentityAssertion,
  Session,
  User,
  Verification,
} from './entities.js'
import type { CredentialId, IdentityId, SessionId, UserId, VerificationId } from './ids.js'
import type { OtpChannel, VerificationPurpose } from './kinds.js'
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
