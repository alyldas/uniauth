import { optionalProp } from '../optional.js'
import type { AuthServiceRuntime } from '../runtime.js'
import { createSessionRecord } from '../sessions.js'
import { audit } from '../support.js'
import {
  AuditEventType,
  AuthIdentityStatus,
  type AuthIdentity,
  type CreateSessionResult,
  type ProviderIdentityAssertion,
  type Session,
  type User,
} from '../../domain/types.js'

export const SignInAuditMode = {
  Exact: 'exact',
  AutoLink: 'auto-link',
  NewUser: 'new-user',
} as const

export type SignInAuditMode = (typeof SignInAuditMode)[keyof typeof SignInAuditMode]

export interface SignInWithAssertionInput {
  readonly now: Date
  readonly sessionExpiresAt?: Date
  readonly metadata?: Record<string, unknown>
}

export async function createSessionForSignIn(
  runtime: AuthServiceRuntime,
  user: User,
  input: SignInWithAssertionInput,
): Promise<CreateSessionResult> {
  return createSessionRecord(runtime, {
    userId: user.id,
    now: input.now,
    ...optionalProp('expiresAt', input.sessionExpiresAt),
    ...optionalProp('metadata', input.metadata),
  })
}

export async function auditSuccessfulSignIn(
  runtime: AuthServiceRuntime,
  mode: SignInAuditMode,
  input: SignInWithAssertionInput,
  user: User,
  identity: AuthIdentity,
  session: Session,
): Promise<void> {
  await audit(runtime, AuditEventType.SignIn, input.now, {
    userId: user.id,
    identityId: identity.id,
    sessionId: session.id,
    metadata: { mode },
  })
}

export async function createUserFromAssertion(
  runtime: AuthServiceRuntime,
  assertion: ProviderIdentityAssertion,
  now: Date,
): Promise<User> {
  const user: User = {
    id: runtime.idGenerator.userId(),
    createdAt: now,
    updatedAt: now,
    ...optionalProp('displayName', assertion.displayName),
    ...(assertion.email && assertion.emailVerified === true ? { email: assertion.email } : {}),
    ...(assertion.phone && assertion.phoneVerified === true ? { phone: assertion.phone } : {}),
  }

  return runtime.repos.userRepo.create(user)
}

export async function createIdentityFromAssertion(
  runtime: AuthServiceRuntime,
  user: User,
  assertion: ProviderIdentityAssertion,
  now: Date,
): Promise<AuthIdentity> {
  const identity: AuthIdentity = {
    id: runtime.idGenerator.identityId(),
    userId: user.id,
    provider: assertion.provider,
    providerUserId: assertion.providerUserId,
    status: AuthIdentityStatus.Active,
    createdAt: now,
    updatedAt: now,
    ...(assertion.email
      ? { email: assertion.email, emailVerified: assertion.emailVerified === true }
      : {}),
    ...(assertion.phone
      ? { phone: assertion.phone, phoneVerified: assertion.phoneVerified === true }
      : {}),
    ...optionalProp('trust', assertion.trust),
    ...optionalProp('metadata', assertion.metadata),
  }

  return runtime.repos.identityRepo.create(identity)
}
