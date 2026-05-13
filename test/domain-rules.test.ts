import { describe, expect, it } from 'vitest'
import {
  AuthIdentityStatus,
  SessionStatus,
  VerificationStatus,
  addSeconds,
  isActiveIdentity,
  isActiveSession,
  isActiveUser,
  isConsumedVerification,
  isExpiredVerification,
  isUsableVerification,
} from '../src'
import { identity, now, user } from './helpers.js'

describe('domain rules', () => {
  it('detects active and disabled users', () => {
    expect(isActiveUser(user())).toBe(true)
    expect(isActiveUser({ ...user('disabled-user'), disabledAt: now })).toBe(false)
  })

  it('detects active and disabled identities', () => {
    expect(isActiveIdentity(identity())).toBe(true)
    expect(
      isActiveIdentity(
        identity({
          status: AuthIdentityStatus.Disabled,
          disabledAt: now,
        }),
      ),
    ).toBe(false)
  })

  it('detects active sessions against status and expiry', () => {
    const activeSession = {
      id: 'ses_1',
      userId: user().id,
      tokenHash: 'hash',
      status: SessionStatus.Active,
      createdAt: now,
      expiresAt: addSeconds(now, 60),
    }

    expect(isActiveSession(activeSession, now)).toBe(true)
    expect(isActiveSession({ ...activeSession, expiresAt: now }, now)).toBe(false)
    expect(isActiveSession({ ...activeSession, status: SessionStatus.Revoked }, now)).toBe(false)
    expect(() =>
      isActiveSession({ ...activeSession, expiresAt: new Date('invalid') }, now),
    ).toThrow('Session expiration time is invalid.')
    expect(() => isActiveSession(activeSession, new Date('invalid'))).toThrow(
      'Session comparison time is invalid.',
    )
  })

  it('detects consumed and expired verifications', () => {
    const verification = {
      id: 'vrf_1',
      purpose: 'sign-in',
      target: 'alice@example.com',
      secretHash: 'hash',
      status: VerificationStatus.Pending,
      createdAt: now,
      expiresAt: addSeconds(now, 60),
    }

    expect(isConsumedVerification(verification)).toBe(false)
    expect(isExpiredVerification(verification, now)).toBe(false)
    expect(isUsableVerification(verification, now)).toBe(true)
    expect(isConsumedVerification({ ...verification, status: VerificationStatus.Consumed })).toBe(
      true,
    )
    expect(isExpiredVerification({ ...verification, expiresAt: now }, now)).toBe(true)
    expect(isUsableVerification({ ...verification, expiresAt: now }, now)).toBe(false)
    expect(() =>
      isExpiredVerification({ ...verification, expiresAt: new Date('invalid') }, now),
    ).toThrow('Verification expiration time is invalid.')
    expect(() => isExpiredVerification(verification, new Date('invalid'))).toThrow(
      'Verification comparison time is invalid.',
    )
  })
})
