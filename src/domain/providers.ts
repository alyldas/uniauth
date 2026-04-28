export type AuthIdentityProvider = string

export const EMAIL_OTP_PROVIDER_ID = 'email-otp'
export const EMAIL_MAGIC_LINK_PROVIDER_ID = 'email-magic-link'
export const PHONE_OTP_PROVIDER_ID = 'phone-otp'
export const PASSWORD_PROVIDER_ID = 'password'

export interface FinishInput {
  readonly code?: string
  readonly state?: string
  readonly payload?: unknown
  readonly metadata?: Record<string, unknown>
}
