export const UniauthErrorCode = {
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

export type UniauthErrorCode = (typeof UniauthErrorCode)[keyof typeof UniauthErrorCode]

export class UniauthError extends Error {
  readonly code: UniauthErrorCode
  readonly details?: Record<string, unknown>

  constructor(code: UniauthErrorCode, message: string, details?: Record<string, unknown>) {
    super(message)
    this.name = 'UniauthError'
    this.code = code
    if (details) {
      this.details = details
    }
  }
}

export function isUniauthError(error: unknown): error is UniauthError {
  return error instanceof UniauthError
}

export function invalidInput(message = 'Invalid auth input.'): UniauthError {
  return new UniauthError(UniauthErrorCode.InvalidInput, message)
}
