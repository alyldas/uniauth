import type { OtpChannel, VerificationPurpose } from '../domain/types.js'

export const RateLimitAction = {
  ProviderSignIn: 'provider:sign-in',
  OtpStart: 'otp:start',
  OtpFinish: 'otp:finish',
  MagicLinkStart: 'magic-link:start',
  MagicLinkFinish: 'magic-link:finish',
  PasswordSignIn: 'password:sign-in',
  PasswordRecoveryStart: 'password-recovery:start',
  PasswordRecoveryFinish: 'password-recovery:finish',
} as const

export type RateLimitAction = (typeof RateLimitAction)[keyof typeof RateLimitAction]

export interface RateLimitAttempt {
  readonly action: RateLimitAction
  readonly key: string
  readonly now: Date
  readonly metadata?: Record<string, unknown>
}

export interface RateLimitDecision {
  readonly allowed: boolean
  readonly retryAfterSeconds?: number
  readonly resetAt?: Date
}

export interface RateLimitedErrorDetails {
  readonly action: RateLimitAction
  readonly retryAfterSeconds?: number
  readonly resetAt?: string
}

export interface RateLimiter {
  consume(input: RateLimitAttempt): Promise<RateLimitDecision>
}

export interface OtpSecretGeneratorInput {
  readonly purpose: VerificationPurpose
  readonly channel: OtpChannel
  readonly target: string
  readonly now: Date
}

export type OtpSecretGenerator = (input: OtpSecretGeneratorInput) => string | Promise<string>

export function rateLimitKey(...parts: readonly string[]): string {
  return parts.join('\u0000')
}

export function isRateLimitedErrorDetails(input: unknown): input is RateLimitedErrorDetails {
  if (!(input && typeof input === 'object')) {
    return false
  }

  const { action, retryAfterSeconds, resetAt } = input as Partial<RateLimitedErrorDetails>

  if (typeof action !== 'string' || !action.trim()) {
    return false
  }

  if (
    retryAfterSeconds !== undefined &&
    (!Number.isFinite(retryAfterSeconds) || retryAfterSeconds < 0)
  ) {
    return false
  }

  if (resetAt !== undefined && typeof resetAt !== 'string') {
    return false
  }

  return true
}
