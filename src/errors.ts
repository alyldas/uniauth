export const UniAuthErrorCode = {
  InvalidInput: 'invalid_input',
  ProviderNotFound: 'provider_not_found',
  UserNotFound: 'user_not_found',
  IdentityNotFound: 'identity_not_found',
  IdentityAlreadyLinked: 'identity_already_linked',
  LastIdentity: 'last_identity',
  PolicyDenied: 'policy_denied',
  ReAuthRequired: 're_auth_required',
  SessionNotFound: 'session_not_found',
  VerificationNotFound: 'verification_not_found',
  VerificationExpired: 'verification_expired',
  VerificationConsumed: 'verification_consumed',
  VerificationInvalidSecret: 'verification_invalid_secret',
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
