import type { AuthServiceRuntime } from './runtime.js'
import { optionalProp } from './optional.js'
import { getActiveUser } from './support.js'
import { resolveSession, touchSession } from './sessions.js'
import type { ResolveSessionContextInput, ResolvedSessionContext } from '../domain/types.js'
import { UniAuthError, UniAuthErrorCode, isUniAuthError } from '../errors.js'

export async function resolveSessionContext(
  runtime: AuthServiceRuntime,
  input: ResolveSessionContextInput,
): Promise<ResolvedSessionContext> {
  const resolvedSession = await resolveSession(runtime, {
    sessionToken: input.sessionToken,
    ...optionalProp('now', input.now),
  })
  const user = await getResolvedSessionUser(runtime, resolvedSession.userId)
  const session = input.touch
    ? await touchSession(runtime, {
        sessionId: resolvedSession.id,
        ...optionalProp('now', input.now),
      })
    : resolvedSession

  return {
    session,
    user,
  }
}

async function getResolvedSessionUser(
  runtime: AuthServiceRuntime,
  userId: ResolvedSessionContext['user']['id'],
): Promise<ResolvedSessionContext['user']> {
  try {
    return await getActiveUser(runtime, userId)
  } catch (error) {
    if (isUniAuthError(error) && error.code === UniAuthErrorCode.UserNotFound) {
      throw new UniAuthError(UniAuthErrorCode.SessionNotFound, 'Session was not found.')
    }

    throw error
  }
}
