import type { AuthIdentity, Session, User, Verification } from './entities.js'
import { AuthIdentityStatus, SessionStatus, VerificationStatus } from './kinds.js'
import { invalidInput } from '../errors.js'

export function isActiveUser(user: Pick<User, 'disabledAt'>): boolean {
  return !user.disabledAt
}

export function isActiveIdentity(identity: Pick<AuthIdentity, 'status' | 'disabledAt'>): boolean {
  return identity.status === AuthIdentityStatus.Active && !identity.disabledAt
}

export function hasActiveSessionStatus(session: Pick<Session, 'status'>): boolean {
  return session.status === SessionStatus.Active
}

export function isActiveSession(
  session: Pick<Session, 'status' | 'expiresAt'>,
  now: Date,
): boolean {
  assertRuleDate(session.expiresAt, 'Session expiration time is invalid.')
  assertRuleDate(now, 'Session comparison time is invalid.')

  return hasActiveSessionStatus(session) && session.expiresAt.getTime() > now.getTime()
}

export function isConsumedVerification(verification: Pick<Verification, 'status'>): boolean {
  return verification.status === VerificationStatus.Consumed
}

export function isExpiredVerification(
  verification: Pick<Verification, 'expiresAt'>,
  now: Date,
): boolean {
  assertRuleDate(verification.expiresAt, 'Verification expiration time is invalid.')
  assertRuleDate(now, 'Verification comparison time is invalid.')

  return verification.expiresAt.getTime() <= now.getTime()
}

export function isUsableVerification(
  verification: Pick<Verification, 'status' | 'expiresAt'>,
  now: Date,
): boolean {
  return !isConsumedVerification(verification) && !isExpiredVerification(verification, now)
}

function assertRuleDate(value: unknown, message: string): asserts value is Date {
  if (!(value instanceof Date) || Number.isNaN(value.getTime())) {
    throw invalidInput(message)
  }
}
