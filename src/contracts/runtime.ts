import type {
  AuditEventId,
  CredentialId,
  IdentityId,
  SessionId,
  UserId,
  VerificationId,
} from '../domain/ids.js'

export interface Clock {
  now(): Date
}

export interface IdGenerator {
  userId(): UserId
  identityId(): IdentityId
  credentialId(): CredentialId
  verificationId(): VerificationId
  sessionId(): SessionId
  auditEventId(): AuditEventId
}

export interface AuthNormalizer {
  normalizeEmail(email: string): string
  normalizePhone(phone: string): string
  normalizeTarget(target: string): string
}

export type AuthValueNormalizer = (value: string) => string

export type AuthTargetNormalizer = (
  target: string,
  helpers: Pick<AuthNormalizer, 'normalizeEmail' | 'normalizePhone'>,
) => string

export interface CreateAuthNormalizerOptions {
  readonly normalizeEmail?: AuthValueNormalizer
  readonly normalizePhone?: AuthValueNormalizer
  readonly normalizeTarget?: AuthTargetNormalizer
}

export interface SecretHasher {
  hash(secret: string): string | Promise<string>
  verify(secret: string, secretHash: string): boolean | Promise<boolean>
}

export interface ScryptSecretHasherOptions {
  readonly cost?: number
  readonly blockSize?: number
  readonly parallelization?: number
  readonly keyLength?: number
  readonly saltByteLength?: number
  readonly maxmem?: number
}
