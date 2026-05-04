import type { UserId, VerificationId } from './ids.js'
import type { OtpChannel } from './kinds.js'

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

export interface ResendEmailMagicLinkSignInInput {
  readonly verificationId: VerificationId
  readonly createLink: (input: EmailMagicLink) => string | Promise<string>
  readonly secret?: string
  readonly ttlSeconds?: number
  readonly now?: Date
  readonly metadata?: Record<string, unknown>
}

export interface CancelEmailMagicLinkSignInInput {
  readonly verificationId: VerificationId
  readonly now?: Date
  readonly metadata?: Record<string, unknown>
}

export interface SignInWithPasswordInput {
  readonly email: string
  readonly password: string
  readonly now?: Date
  readonly sessionExpiresAt?: Date
  readonly metadata?: Record<string, unknown>
}

export interface CurrentAccountPasswordReAuthConfirmation {
  readonly userId: UserId
  readonly reAuthenticatedAt: Date
}

export interface ConfirmCurrentAccountPasswordByTokenInput {
  readonly sessionToken: string
  readonly currentPassword: string
  readonly now?: Date
}

export interface SetPasswordInput {
  readonly userId: UserId
  readonly email: string
  readonly password: string
  readonly reAuthenticatedAt?: Date
  readonly now?: Date
  readonly metadata?: Record<string, unknown>
}

export interface SetCurrentAccountPasswordByTokenInput {
  readonly sessionToken: string
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

export interface ChangeCurrentAccountPasswordByTokenInput {
  readonly sessionToken: string
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

export interface ResendEmailPasswordRecoveryInput {
  readonly verificationId: VerificationId
  readonly createLink: (input: EmailPasswordRecoveryLink) => string | Promise<string>
  readonly secret?: string
  readonly ttlSeconds?: number
  readonly now?: Date
  readonly metadata?: Record<string, unknown>
}

export interface CancelEmailPasswordRecoveryInput {
  readonly verificationId: VerificationId
  readonly now?: Date
  readonly metadata?: Record<string, unknown>
}
