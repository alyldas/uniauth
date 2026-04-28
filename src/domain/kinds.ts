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
