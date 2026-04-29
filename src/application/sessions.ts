import type { AuthServiceRuntime } from './runtime.js'
import { optionalProp } from './optional.js'
import { audit, getActiveUser } from './support.js'
import type {
  CreateSessionInput,
  CreateSessionResult,
  ResolveSessionInput,
  Session,
  SessionId,
  TouchSessionInput,
} from '../domain/types.js'
import { AuditEventType, SessionStatus } from '../domain/types.js'
import { UniAuthError, UniAuthErrorCode, invalidInput } from '../errors.js'
import { generateSecret, hashSecret } from '../utils/secrets.js'
import { addSeconds, assertValidDate } from '../utils/time.js'

export async function createSession(
  runtime: AuthServiceRuntime,
  input: CreateSessionInput,
): Promise<CreateSessionResult> {
  return runtime.transaction.run(async () => {
    const now = input.now ?? runtime.clock.now()
    await getActiveUser(runtime, input.userId)
    return createSessionRecord(runtime, { ...input, now })
  })
}

export async function revokeSession(
  runtime: AuthServiceRuntime,
  sessionId: SessionId,
): Promise<void> {
  await runtime.transaction.run(async () => {
    const now = runtime.clock.now()
    const session = await runtime.repos.sessionRepo.findById(sessionId)

    if (!session) {
      throw new UniAuthError(UniAuthErrorCode.SessionNotFound, 'Session was not found.')
    }

    await runtime.repos.sessionRepo.update(session.id, {
      status: SessionStatus.Revoked,
      revokedAt: now,
    })
    await audit(runtime, AuditEventType.SessionRevoked, now, {
      userId: session.userId,
      sessionId: session.id,
    })
  })
}

export async function resolveSession(
  runtime: AuthServiceRuntime,
  input: ResolveSessionInput,
): Promise<Session> {
  const now = input.now ?? runtime.clock.now()
  const sessionToken = input.sessionToken.trim()

  if (!sessionToken) {
    throw invalidInput('Session token is required.')
  }

  const session = await runtime.repos.sessionRepo.findByTokenHash(hashSecret(sessionToken))

  if (
    !session ||
    session.status !== SessionStatus.Active ||
    session.expiresAt.getTime() <= now.getTime()
  ) {
    throw new UniAuthError(UniAuthErrorCode.SessionNotFound, 'Session was not found.')
  }

  return session
}

export async function touchSession(
  runtime: AuthServiceRuntime,
  input: TouchSessionInput,
): Promise<Session> {
  return runtime.transaction.run(async () => {
    const now = input.now ?? runtime.clock.now()

    assertValidDate(now, 'Session activity time is invalid.')

    const session = await requireActiveSession(runtime, input.sessionId, now)

    if (session.lastSeenAt && session.lastSeenAt.getTime() >= now.getTime()) {
      return session
    }

    return runtime.repos.sessionRepo.update(session.id, {
      lastSeenAt: now,
    })
  })
}

export async function createSessionRecord(
  runtime: AuthServiceRuntime,
  input: CreateSessionInput & { readonly now: Date },
): Promise<CreateSessionResult> {
  const sessionToken = generateSecret()
  const expiresAt = resolveSessionExpiresAt(runtime, input)
  const session: Session = {
    id: runtime.idGenerator.sessionId(),
    userId: input.userId,
    tokenHash: hashSecret(sessionToken),
    status: SessionStatus.Active,
    createdAt: input.now,
    expiresAt,
    ...optionalProp('metadata', input.metadata),
  }

  const created = await runtime.repos.sessionRepo.create(session)
  await audit(runtime, AuditEventType.SessionCreated, input.now, {
    userId: created.userId,
    sessionId: created.id,
  })

  return { session: created, sessionToken }
}

function resolveSessionExpiresAt(
  runtime: AuthServiceRuntime,
  input: CreateSessionInput & { readonly now: Date },
): Date {
  assertValidDate(input.now, 'Session creation time is invalid.')

  if (input.expiresAt) {
    assertValidDate(input.expiresAt, 'Session expiration time is invalid.')

    if (input.expiresAt.getTime() < input.now.getTime()) {
      throw invalidInput('Session expiration time cannot be in the past.')
    }

    return input.expiresAt
  }

  if (!Number.isFinite(runtime.sessionTtlSeconds) || runtime.sessionTtlSeconds < 0) {
    throw invalidInput('Session TTL must be a non-negative number of seconds.')
  }

  return addSeconds(input.now, runtime.sessionTtlSeconds)
}

async function requireActiveSession(
  runtime: AuthServiceRuntime,
  sessionId: SessionId,
  now: Date,
): Promise<Session> {
  const session = await runtime.repos.sessionRepo.findById(sessionId)

  if (
    !session ||
    session.status !== SessionStatus.Active ||
    session.expiresAt.getTime() <= now.getTime()
  ) {
    throw new UniAuthError(UniAuthErrorCode.SessionNotFound, 'Session was not found.')
  }

  return session
}
