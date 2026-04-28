import type { AuditEventId, IdentityId, SessionId, UserId } from './ids.js'

export const AuditEventType = {
  SignIn: 'auth.sign_in',
  IdentityLinked: 'auth.identity_linked',
  IdentityUnlinked: 'auth.identity_unlinked',
  AccountsMerged: 'auth.accounts_merged',
  SessionCreated: 'auth.session_created',
  SessionRevoked: 'auth.session_revoked',
  VerificationCreated: 'auth.verification_created',
  VerificationConsumed: 'auth.verification_consumed',
  PolicyDenied: 'auth.policy_denied',
  RateLimited: 'auth.rate_limited',
} as const

export type AuditEventType = (typeof AuditEventType)[keyof typeof AuditEventType]

export interface AuditEvent {
  readonly id: AuditEventId
  readonly type: AuditEventType
  readonly occurredAt: Date
  readonly userId?: UserId
  readonly identityId?: IdentityId
  readonly sessionId?: SessionId
  readonly metadata?: Record<string, unknown>
}
