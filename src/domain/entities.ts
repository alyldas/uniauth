import type { CredentialId, UserId, IdentityId, SessionId, VerificationId } from './ids.js'
import type {
  AuthIdentityStatus,
  CredentialType,
  OtpChannel,
  ProviderTrustLevel,
  SessionStatus,
  VerificationPurpose,
  VerificationStatus,
} from './kinds.js'
import type { AuthIdentityProvider } from './providers.js'

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
  readonly tokenHash: string
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
