import type { AuthIdentity, Session, User, Verification } from './entities.js'
import { AuthIdentityStatus, SessionStatus, VerificationStatus } from './kinds.js'

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
  return hasActiveSessionStatus(session) && session.expiresAt.getTime() > now.getTime()
}

export function isConsumedVerification(verification: Pick<Verification, 'status'>): boolean {
  return verification.status === VerificationStatus.Consumed
}

export function isExpiredVerification(
  verification: Pick<Verification, 'expiresAt'>,
  now: Date,
): boolean {
  return verification.expiresAt.getTime() <= now.getTime()
}

export function isUsableVerification(
  verification: Pick<Verification, 'status' | 'expiresAt'>,
  now: Date,
): boolean {
  return !isConsumedVerification(verification) && !isExpiredVerification(verification, now)
}
