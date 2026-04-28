declare const brand: unique symbol

export type Brand<Value, Name extends string> = Value & { readonly [brand]: Name }

export type UserId = Brand<string, 'UserId'>
export type IdentityId = Brand<string, 'IdentityId'>
export type CredentialId = Brand<string, 'CredentialId'>
export type VerificationId = Brand<string, 'VerificationId'>
export type SessionId = Brand<string, 'SessionId'>
export type AuditEventId = Brand<string, 'AuditEventId'>

export function asUserId(value: string): UserId {
  return value as UserId
}

export function asIdentityId(value: string): IdentityId {
  return value as IdentityId
}

export function asCredentialId(value: string): CredentialId {
  return value as CredentialId
}

export function asVerificationId(value: string): VerificationId {
  return value as VerificationId
}

export function asSessionId(value: string): SessionId {
  return value as SessionId
}

export function asAuditEventId(value: string): AuditEventId {
  return value as AuditEventId
}
