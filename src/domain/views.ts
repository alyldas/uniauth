import type { AuditEvent, AuditEventCursor } from './audit.js'
import type { AuthIdentity, Credential, Session, User, Verification } from './entities.js'
import type { ProviderTrustLevel } from './kinds.js'
import { isExpiredVerification, isUsableVerification } from './rules.js'

export interface AccountSecurityUserView {
  readonly id: User['id']
  readonly displayName?: string
  readonly email?: string
  readonly phone?: string
  readonly createdAt: Date
  readonly updatedAt: Date
  readonly disabledAt?: Date
}

export interface AccountSecurityIdentityView {
  readonly id: AuthIdentity['id']
  readonly provider: AuthIdentity['provider']
  readonly status: AuthIdentity['status']
  readonly email?: string
  readonly emailVerified?: boolean
  readonly phone?: string
  readonly phoneVerified?: boolean
  readonly trustLevel?: ProviderTrustLevel
  readonly createdAt: Date
  readonly updatedAt: Date
  readonly disabledAt?: Date
}

export interface AccountSecurityCredentialView {
  readonly id: Credential['id']
  readonly type: Credential['type']
  readonly subject: Credential['subject']
  readonly createdAt: Date
  readonly updatedAt: Date
}

export interface AccountSecuritySessionView {
  readonly id: Session['id']
  readonly status: Session['status']
  readonly createdAt: Date
  readonly expiresAt: Date
  readonly revokedAt?: Date
  readonly lastSeenAt?: Date
}

export interface AccountSecuritySnapshot {
  readonly user: AccountSecurityUserView
  readonly identities: readonly AccountSecurityIdentityView[]
  readonly credentials: readonly AccountSecurityCredentialView[]
  readonly sessions: readonly AccountSecuritySessionView[]
}

export interface CurrentAccountSecuritySnapshot {
  readonly account: AccountSecuritySnapshot
  readonly currentSessionId: Session['id']
}

export interface CurrentAccountInspectionSnapshot extends CurrentAccountSecuritySnapshot {
  readonly auditEvents: readonly AuditEventView[]
  readonly nextAuditCursor?: AuditEventCursor
}

export interface AuditEventView {
  readonly id: AuditEvent['id']
  readonly type: AuditEvent['type']
  readonly occurredAt: Date
  readonly userId?: AuditEvent['userId']
  readonly identityId?: AuditEvent['identityId']
  readonly sessionId?: AuditEvent['sessionId']
}

export interface AccountInspectionSnapshot {
  readonly account: AccountSecuritySnapshot
  readonly auditEvents: readonly AuditEventView[]
  readonly nextAuditCursor?: AuditEventCursor
}

export interface VerificationStatusView {
  readonly id: Verification['id']
  readonly purpose: Verification['purpose']
  readonly status: Verification['status']
  readonly expiresAt: Date
  readonly consumedAt?: Date
}

export interface VerificationResendWindow extends VerificationStatusView {
  readonly provider?: Verification['provider']
  readonly channel?: Verification['channel']
  readonly resendAllowed: boolean
  readonly expired: boolean
  readonly resendAvailableAt: Date
  readonly cooldownSeconds: number
  readonly cooldownRemainingSeconds: number
}

export function toAccountSecurityUserView(user: User): AccountSecurityUserView {
  return {
    id: user.id,
    ...(user.displayName ? { displayName: user.displayName } : {}),
    ...(user.email ? { email: user.email } : {}),
    ...(user.phone ? { phone: user.phone } : {}),
    createdAt: user.createdAt,
    updatedAt: user.updatedAt,
    ...(user.disabledAt ? { disabledAt: user.disabledAt } : {}),
  }
}

export function toAccountSecurityIdentityView(identity: AuthIdentity): AccountSecurityIdentityView {
  return {
    id: identity.id,
    provider: identity.provider,
    status: identity.status,
    ...(identity.email ? { email: identity.email } : {}),
    ...(identity.emailVerified !== undefined ? { emailVerified: identity.emailVerified } : {}),
    ...(identity.phone ? { phone: identity.phone } : {}),
    ...(identity.phoneVerified !== undefined ? { phoneVerified: identity.phoneVerified } : {}),
    ...(identity.trust?.level ? { trustLevel: identity.trust.level } : {}),
    createdAt: identity.createdAt,
    updatedAt: identity.updatedAt,
    ...(identity.disabledAt ? { disabledAt: identity.disabledAt } : {}),
  }
}

export function toAccountSecurityCredentialView(
  credential: Credential,
): AccountSecurityCredentialView {
  return {
    id: credential.id,
    type: credential.type,
    subject: credential.subject,
    createdAt: credential.createdAt,
    updatedAt: credential.updatedAt,
  }
}

export function toAccountSecuritySessionView(session: Session): AccountSecuritySessionView {
  return {
    id: session.id,
    status: session.status,
    createdAt: session.createdAt,
    expiresAt: session.expiresAt,
    ...(session.revokedAt ? { revokedAt: session.revokedAt } : {}),
    ...(session.lastSeenAt ? { lastSeenAt: session.lastSeenAt } : {}),
  }
}

export function toAccountSecuritySnapshot(input: {
  readonly user: User
  readonly identities: readonly AuthIdentity[]
  readonly credentials: readonly Credential[]
  readonly sessions: readonly Session[]
}): AccountSecuritySnapshot {
  return {
    user: toAccountSecurityUserView(input.user),
    identities: input.identities.map((identity) => toAccountSecurityIdentityView(identity)),
    credentials: input.credentials.map((credential) => toAccountSecurityCredentialView(credential)),
    sessions: input.sessions.map((session) => toAccountSecuritySessionView(session)),
  }
}

export function toAuditEventView(event: AuditEvent): AuditEventView {
  return {
    id: event.id,
    type: event.type,
    occurredAt: event.occurredAt,
    ...(event.userId ? { userId: event.userId } : {}),
    ...(event.identityId ? { identityId: event.identityId } : {}),
    ...(event.sessionId ? { sessionId: event.sessionId } : {}),
  }
}

export function toAccountInspectionSnapshot(input: {
  readonly account: AccountSecuritySnapshot
  readonly auditEvents: readonly AuditEvent[]
  readonly nextAuditCursor?: AuditEventCursor
}): AccountInspectionSnapshot {
  return {
    account: input.account,
    auditEvents: input.auditEvents.map((event) => toAuditEventView(event)),
    ...(input.nextAuditCursor ? { nextAuditCursor: input.nextAuditCursor } : {}),
  }
}

export function toCurrentAccountInspectionSnapshot(input: {
  readonly account: AccountSecuritySnapshot
  readonly currentSessionId: Session['id']
  readonly auditEvents: readonly AuditEvent[]
  readonly nextAuditCursor?: AuditEventCursor
}): CurrentAccountInspectionSnapshot {
  return {
    account: input.account,
    currentSessionId: input.currentSessionId,
    auditEvents: input.auditEvents.map((event) => toAuditEventView(event)),
    ...(input.nextAuditCursor ? { nextAuditCursor: input.nextAuditCursor } : {}),
  }
}

export function toVerificationStatusView(verification: Verification): VerificationStatusView {
  return {
    id: verification.id,
    purpose: verification.purpose,
    status: verification.status,
    expiresAt: verification.expiresAt,
    ...(verification.consumedAt ? { consumedAt: verification.consumedAt } : {}),
  }
}

export function toVerificationResendWindow(
  verification: Verification,
  input: {
    readonly now: Date
    readonly cooldownSeconds: number
  },
): VerificationResendWindow {
  const resendAvailableAt = new Date(
    verification.createdAt.getTime() + input.cooldownSeconds * 1000,
  )
  const cooldownRemainingSeconds = Math.max(
    0,
    Math.ceil((resendAvailableAt.getTime() - input.now.getTime()) / 1000),
  )
  const expired = isExpiredVerification(verification, input.now)
  const resendAllowed =
    isUsableVerification(verification, input.now) && cooldownRemainingSeconds === 0

  return {
    ...toVerificationStatusView(verification),
    ...(verification.provider ? { provider: verification.provider } : {}),
    ...(verification.channel ? { channel: verification.channel } : {}),
    resendAllowed,
    expired,
    resendAvailableAt,
    cooldownSeconds: input.cooldownSeconds,
    cooldownRemainingSeconds,
  }
}
