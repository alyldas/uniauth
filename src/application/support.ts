import type { AuthPolicyAction } from './policy.js'
import { optionalProp } from './optional.js'
import type { AuthServiceRuntime } from './runtime.js'
import type {
  AuditEvent,
  AuthIdentity,
  IdentityId,
  SessionId,
  User,
  UserId,
} from '../domain/types.js'
import { AuditEventType, AuthIdentityStatus } from '../domain/types.js'
import { UniAuthError, UniAuthErrorCode, rateLimited } from '../errors.js'
import type { RateLimitAttempt } from '../ports.js'

const PolicyDenialReason = {
  ReAuthRequired: 're-auth-required',
} as const

export function isActiveIdentity(identity: AuthIdentity): boolean {
  return identity.status === AuthIdentityStatus.Active && !identity.disabledAt
}

export async function getActiveUser(runtime: AuthServiceRuntime, userId: UserId): Promise<User> {
  const user = await runtime.repos.userRepo.findById(userId)

  if (!user || user.disabledAt) {
    throw new UniAuthError(UniAuthErrorCode.UserNotFound, 'User was not found.')
  }

  return user
}

export async function getActiveIdentity(
  runtime: AuthServiceRuntime,
  identityId: IdentityId,
): Promise<AuthIdentity> {
  const identity = await runtime.repos.identityRepo.findById(identityId)

  if (!identity || !isActiveIdentity(identity)) {
    throw new UniAuthError(UniAuthErrorCode.IdentityNotFound, 'Identity was not found.')
  }

  return identity
}

export async function ensureReAuth(
  runtime: AuthServiceRuntime,
  action: AuthPolicyAction,
  userId: UserId,
  reAuthenticatedAt: Date | undefined,
  now: Date,
): Promise<void> {
  const required = await runtime.policy.requiresReAuth({
    action,
    userId,
    reAuthenticatedAt,
    now,
  })

  if (required) {
    await audit(runtime, AuditEventType.PolicyDenied, now, {
      userId,
      metadata: { reason: PolicyDenialReason.ReAuthRequired, action },
    })
    throw new UniAuthError(UniAuthErrorCode.ReAuthRequired, 'Recent authentication is required.')
  }
}

export async function enforceRateLimit(
  runtime: AuthServiceRuntime,
  input: RateLimitAttempt,
): Promise<void> {
  if (!runtime.rateLimiter) {
    return
  }

  const decision = await runtime.rateLimiter.consume(input)

  if (decision.allowed) {
    return
  }

  await audit(runtime, AuditEventType.RateLimited, input.now, {
    metadata: {
      action: input.action,
      ...optionalProp('retryAfterSeconds', decision.retryAfterSeconds),
      ...optionalProp('resetAt', decision.resetAt?.toISOString()),
    },
  })

  throw rateLimited({
    action: input.action,
    ...optionalProp('retryAfterSeconds', decision.retryAfterSeconds),
    ...optionalProp('resetAt', decision.resetAt?.toISOString()),
  })
}

export function rateLimitKey(...parts: readonly string[]): string {
  return parts.join('\u0000')
}

export async function audit(
  runtime: AuthServiceRuntime,
  type: AuditEventType,
  occurredAt: Date,
  input: {
    readonly userId?: UserId
    readonly identityId?: IdentityId
    readonly sessionId?: SessionId
    readonly metadata?: Record<string, unknown>
  } = {},
): Promise<void> {
  const event: AuditEvent = {
    id: runtime.idGenerator.auditEventId(),
    type,
    occurredAt,
    ...optionalProp('userId', input.userId),
    ...optionalProp('identityId', input.identityId),
    ...optionalProp('sessionId', input.sessionId),
    ...optionalProp('metadata', input.metadata),
  }

  await runtime.repos.auditLogRepo.append(event)
}
