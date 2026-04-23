export const UniAuthErrorCode = {
  InvalidInput: 'invalid_input',
  ProviderNotFound: 'provider_not_found',
  InvalidCredentials: 'invalid_credentials',
  UserNotFound: 'user_not_found',
  IdentityNotFound: 'identity_not_found',
  IdentityAlreadyLinked: 'identity_already_linked',
  CredentialNotFound: 'credential_not_found',
  CredentialAlreadyExists: 'credential_already_exists',
  LastIdentity: 'last_identity',
  PolicyDenied: 'policy_denied',
  ReAuthRequired: 're_auth_required',
  SessionNotFound: 'session_not_found',
  VerificationNotFound: 'verification_not_found',
  VerificationExpired: 'verification_expired',
  VerificationConsumed: 'verification_consumed',
  VerificationInvalidSecret: 'verification_invalid_secret',
  RateLimited: 'rate_limited',
} as const

export type UniAuthErrorCode = (typeof UniAuthErrorCode)[keyof typeof UniAuthErrorCode]

export class UniAuthError extends Error {
  readonly code: UniAuthErrorCode
  readonly details?: Record<string, unknown>

  constructor(code: UniAuthErrorCode, message: string, details?: Record<string, unknown>) {
    super(message)
    this.name = 'UniAuthError'
    this.code = code
    if (details) {
      this.details = details
    }
  }
}

export function isUniAuthError(error: unknown): error is UniAuthError {
  return error instanceof UniAuthError
}

export function invalidInput(message = 'Invalid auth input.'): UniAuthError {
  return new UniAuthError(UniAuthErrorCode.InvalidInput, message)
}

export function invalidCredentials(): UniAuthError {
  return new UniAuthError(UniAuthErrorCode.InvalidCredentials, 'Email or password is invalid.')
}

export function rateLimited(details?: Record<string, unknown>): UniAuthError {
  return new UniAuthError(UniAuthErrorCode.RateLimited, 'Too many auth attempts.', details)
}
