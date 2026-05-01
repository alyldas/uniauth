import { describe, expect, it } from 'vitest'
import {
  AuditEventType,
  AuthIdentityStatus,
  SessionStatus,
  VerificationStatus,
  asAuditEventId,
  asCredentialId,
  asIdentityId,
  asSessionId,
  asVerificationId,
  toAccountInspectionSnapshot,
  toAccountSecurityCredentialView,
  toAccountSecurityIdentityView,
  toAccountSecuritySessionView,
  toAccountSecuritySnapshot,
  toAccountSecurityUserView,
  toAuditEventView,
  toVerificationStatusView,
  type Credential,
  type Session,
  type Verification,
} from '../src'
import { identity, now, user } from './helpers.js'

describe('safe projection helpers', () => {
  it('maps account-security views without sensitive fields', () => {
    const sourceUser = {
      ...user('user-42'),
      displayName: 'Alice',
      email: 'alice@example.com',
      phone: '+15551234567',
      disabledAt: new Date('2026-01-03T00:00:00.000Z'),
      metadata: { internal: true },
    }
    const sourceIdentity = identity({
      id: asIdentityId('identity-42'),
      status: AuthIdentityStatus.Active,
      provider: 'oauth-demo',
      providerUserId: 'provider-subject',
      email: 'alice@example.com',
      emailVerified: true,
      phone: '+15551234567',
      phoneVerified: true,
      trust: {
        level: 'trusted',
        signals: ['signed-claim'],
        metadata: { score: 7 },
      },
      disabledAt: new Date('2026-01-04T00:00:00.000Z'),
      metadata: { internal: true },
    })
    const credential: Credential = {
      id: asCredentialId('credential-42'),
      userId: sourceUser.id,
      type: 'password',
      subject: 'alice@example.com',
      passwordHash: 'secret-hash',
      createdAt: now,
      updatedAt: now,
      metadata: { internal: true },
    }
    const session: Session = {
      id: asSessionId('session-42'),
      userId: sourceUser.id,
      tokenHash: 'token-hash',
      status: SessionStatus.Active,
      createdAt: now,
      expiresAt: new Date('2026-01-02T00:00:00.000Z'),
      lastSeenAt: new Date('2026-01-01T00:30:00.000Z'),
      metadata: { internal: true },
    }

    const userView = toAccountSecurityUserView(sourceUser)
    const identityView = toAccountSecurityIdentityView(sourceIdentity)
    const credentialView = toAccountSecurityCredentialView(credential)
    const sessionView = toAccountSecuritySessionView(session)
    const snapshot = toAccountSecuritySnapshot({
      user: sourceUser,
      identities: [sourceIdentity],
      credentials: [credential],
      sessions: [session],
    })

    expect(userView).toEqual({
      id: sourceUser.id,
      displayName: 'Alice',
      email: 'alice@example.com',
      phone: '+15551234567',
      createdAt: now,
      updatedAt: now,
      disabledAt: sourceUser.disabledAt,
    })
    expect(identityView).toEqual({
      id: sourceIdentity.id,
      provider: 'oauth-demo',
      status: AuthIdentityStatus.Active,
      email: 'alice@example.com',
      emailVerified: true,
      phone: '+15551234567',
      phoneVerified: true,
      trustLevel: 'trusted',
      createdAt: now,
      updatedAt: now,
      disabledAt: sourceIdentity.disabledAt,
    })
    expect(identityView).not.toHaveProperty('providerUserId')
    expect(identityView).not.toHaveProperty('metadata')
    expect(credentialView).toEqual({
      id: credential.id,
      type: 'password',
      subject: 'alice@example.com',
      createdAt: now,
      updatedAt: now,
    })
    expect(credentialView).not.toHaveProperty('passwordHash')
    expect(sessionView).toEqual({
      id: session.id,
      status: SessionStatus.Active,
      createdAt: now,
      expiresAt: session.expiresAt,
      lastSeenAt: session.lastSeenAt,
    })
    expect(sessionView).not.toHaveProperty('tokenHash')
    expect(snapshot).toEqual({
      user: userView,
      identities: [identityView],
      credentials: [credentialView],
      sessions: [sessionView],
    })
  })

  it('handles sparse account-security inputs and consumed verification status', () => {
    const sparseUser = user('user-7')
    const sparseIdentity = identity({
      id: asIdentityId('identity-7'),
      status: AuthIdentityStatus.Disabled,
      provider: 'password',
      providerUserId: 'user-7',
    })
    const revokedAt = new Date('2026-01-05T00:00:00.000Z')
    const sparseSession: Session = {
      id: asSessionId('session-7'),
      userId: sparseUser.id,
      tokenHash: 'token-hash',
      status: SessionStatus.Revoked,
      createdAt: now,
      expiresAt: new Date('2026-01-06T00:00:00.000Z'),
      revokedAt,
    }
    const consumedAt = new Date('2026-01-01T00:05:00.000Z')
    const consumedVerification: Verification = {
      id: asVerificationId('verification-7'),
      purpose: 'link',
      target: '+15551234567',
      secretHash: 'secret-hash',
      status: VerificationStatus.Consumed,
      createdAt: now,
      expiresAt: new Date('2026-01-01T00:10:00.000Z'),
      consumedAt,
    }

    expect(toAccountSecurityUserView(sparseUser)).toEqual({
      id: sparseUser.id,
      createdAt: now,
      updatedAt: now,
    })
    expect(toAccountSecurityIdentityView(sparseIdentity)).toEqual({
      id: sparseIdentity.id,
      provider: 'password',
      status: AuthIdentityStatus.Disabled,
      createdAt: now,
      updatedAt: now,
    })
    expect(toAccountSecuritySessionView(sparseSession)).toEqual({
      id: sparseSession.id,
      status: SessionStatus.Revoked,
      createdAt: now,
      expiresAt: sparseSession.expiresAt,
      revokedAt,
    })
    expect(toVerificationStatusView(consumedVerification)).toEqual({
      id: consumedVerification.id,
      purpose: consumedVerification.purpose,
      status: VerificationStatus.Consumed,
      expiresAt: consumedVerification.expiresAt,
      consumedAt,
    })
  })

  it('maps verification status without target or secret hash', () => {
    const verification: Verification = {
      id: asVerificationId('verification-42'),
      purpose: 'sign-in',
      target: 'alice@example.com',
      secretHash: 'secret-hash',
      status: VerificationStatus.Pending,
      createdAt: now,
      expiresAt: new Date('2026-01-01T00:10:00.000Z'),
      metadata: { internal: true },
    }

    const view = toVerificationStatusView(verification)

    expect(view).toEqual({
      id: verification.id,
      purpose: verification.purpose,
      status: VerificationStatus.Pending,
      expiresAt: verification.expiresAt,
    })
    expect(view).not.toHaveProperty('target')
    expect(view).not.toHaveProperty('secretHash')
    expect(view).not.toHaveProperty('metadata')
  })

  it('maps trusted inspection views without leaking audit metadata', () => {
    const userView = toAccountSecurityUserView(user('user-9'))
    const identityOnlyAuditView = toAuditEventView({
      id: asAuditEventId('audit-7'),
      type: AuditEventType.IdentityLinked,
      occurredAt: now,
      identityId: asIdentityId('identity-7'),
      metadata: { internal: true },
    })
    const inspectionSnapshot = toAccountInspectionSnapshot({
      account: {
        user: userView,
        identities: [],
        credentials: [],
        sessions: [],
      },
      auditEvents: [
        {
          id: asAuditEventId('audit-9'),
          type: AuditEventType.PolicyDenied,
          occurredAt: now,
          userId: user('user-9').id,
          metadata: { internal: true },
        },
      ],
    })

    expect(
      toAuditEventView({
        id: asAuditEventId('audit-8'),
        type: AuditEventType.SessionCreated,
        occurredAt: now,
        userId: user('user-8').id,
        sessionId: asSessionId('session-8'),
        metadata: { internal: true },
      }),
    ).toEqual({
      id: asAuditEventId('audit-8'),
      type: AuditEventType.SessionCreated,
      occurredAt: now,
      userId: user('user-8').id,
      sessionId: asSessionId('session-8'),
    })
    expect(identityOnlyAuditView).toEqual({
      id: asAuditEventId('audit-7'),
      type: AuditEventType.IdentityLinked,
      occurredAt: now,
      identityId: asIdentityId('identity-7'),
    })
    expect(inspectionSnapshot).toEqual({
      account: {
        user: userView,
        identities: [],
        credentials: [],
        sessions: [],
      },
      auditEvents: [
        {
          id: asAuditEventId('audit-9'),
          type: AuditEventType.PolicyDenied,
          occurredAt: now,
          userId: user('user-9').id,
        },
      ],
    })
    expect(inspectionSnapshot.auditEvents[0]).not.toHaveProperty('metadata')
  })
})
