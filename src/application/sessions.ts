import type { AuthServiceRuntime } from './runtime.js'
import { optionalProp } from './optional.js'
import { audit, getActiveUser } from './support.js'
import type { CreateSessionInput, Session, SessionId } from '../domain/types.js'
import { AuditEventType, SessionStatus } from '../domain/types.js'
import { UniAuthError, UniAuthErrorCode } from '../errors.js'
import { addSeconds } from '../utils/time.js'

export async function createSession(
  runtime: AuthServiceRuntime,
  input: CreateSessionInput,
): Promise<Session> {
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

export async function createSessionRecord(
  runtime: AuthServiceRuntime,
  input: CreateSessionInput & { readonly now: Date },
): Promise<Session> {
  const session: Session = {
    id: runtime.idGenerator.sessionId(),
    userId: input.userId,
    status: SessionStatus.Active,
    createdAt: input.now,
    expiresAt: input.expiresAt ?? addSeconds(input.now, runtime.sessionTtlSeconds),
    ...optionalProp('metadata', input.metadata),
  }

  const created = await runtime.repos.sessionRepo.create(session)
  await audit(runtime, AuditEventType.SessionCreated, input.now, {
    userId: created.userId,
    sessionId: created.id,
  })

  return created
}
