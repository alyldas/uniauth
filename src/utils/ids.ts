import { randomUUID } from 'node:crypto'
import {
  asAuditEventId,
  asIdentityId,
  asSessionId,
  asUserId,
  asVerificationId,
  type AuditEventId,
  type IdGenerator,
  type IdentityId,
  type SessionId,
  type UserId,
  type VerificationId,
} from '../domain/types.js'

export function createRandomIdGenerator(): IdGenerator {
  return {
    userId: () => asUserId(`usr_${randomUUID()}`),
    identityId: () => asIdentityId(`idn_${randomUUID()}`),
    verificationId: () => asVerificationId(`vrf_${randomUUID()}`),
    sessionId: () => asSessionId(`ses_${randomUUID()}`),
    auditEventId: () => asAuditEventId(`aud_${randomUUID()}`),
  }
}

export function createSequentialIdGenerator(prefix = 'test'): IdGenerator {
  let counter = 0
  const next = (kind: string): string => `${prefix}_${kind}_${++counter}`

  return {
    userId: (): UserId => asUserId(next('usr')),
    identityId: (): IdentityId => asIdentityId(next('idn')),
    verificationId: (): VerificationId => asVerificationId(next('vrf')),
    sessionId: (): SessionId => asSessionId(next('ses')),
    auditEventId: (): AuditEventId => asAuditEventId(next('aud')),
  }
}
