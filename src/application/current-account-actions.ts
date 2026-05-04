import { unlink } from './accounts.js'
import { optionalProp } from './optional.js'
import { changePassword, setPassword } from './passwords.js'
import type { AuthServiceRuntime } from './runtime.js'
import { resolveSessionContext } from './session-context.js'
import { revokeStoredSession } from './sessions.js'
import type {
  ChangeCurrentAccountPasswordByTokenInput,
  Credential,
  RevokeOwnedSessionByTokenInput,
  RevokeOwnedSessionByTokenResult,
  SetCurrentAccountPasswordByTokenInput,
  UnlinkCurrentIdentityByTokenInput,
} from '../domain/types.js'
import { isActiveSession } from '../domain/types.js'
import { UniAuthError, UniAuthErrorCode, invalidInput } from '../errors.js'

export async function revokeOwnedSessionByToken(
  runtime: AuthServiceRuntime,
  input: RevokeOwnedSessionByTokenInput,
): Promise<RevokeOwnedSessionByTokenResult> {
  return runtime.transaction.run(async () => {
    const now = input.now ?? runtime.clock.now()
    const { session, user } = await resolveSessionContext(runtime, {
      sessionToken: input.sessionToken,
      now,
    })
    const target = await runtime.repos.sessionRepo.findById(input.targetSessionId)

    if (!target || target.userId !== user.id || !isActiveSession(target, now)) {
      throw new UniAuthError(UniAuthErrorCode.SessionNotFound, 'Session was not found.')
    }

    await revokeStoredSession(runtime, target.id, now)

    return {
      currentSessionId: session.id,
      revokedSessionId: target.id,
      revokedCurrentSession: target.id === session.id,
    }
  })
}

export async function unlinkCurrentIdentityByToken(
  runtime: AuthServiceRuntime,
  input: UnlinkCurrentIdentityByTokenInput,
): Promise<void> {
  return runtime.transaction.run(async () => {
    const now = input.now ?? runtime.clock.now()
    const { user } = await resolveSessionContext(runtime, {
      sessionToken: input.sessionToken,
      now,
    })

    await unlink(runtime, {
      userId: user.id,
      identityId: input.identityId,
      ...optionalProp('reAuthenticatedAt', input.reAuthenticatedAt),
      now,
      ...(input.metadata ? { metadata: input.metadata } : {}),
    })
  })
}

export async function setCurrentAccountPasswordByToken(
  runtime: AuthServiceRuntime,
  input: SetCurrentAccountPasswordByTokenInput,
): Promise<Credential> {
  return runtime.transaction.run(async () => {
    const now = input.now ?? runtime.clock.now()
    const { user } = await resolveSessionContext(runtime, {
      sessionToken: input.sessionToken,
      now,
    })
    const email = user.email?.trim()

    if (!email) {
      throw invalidInput('Password setup requires a trusted email address.')
    }

    return setPassword(runtime, {
      userId: user.id,
      email,
      password: input.password,
      ...optionalProp('reAuthenticatedAt', input.reAuthenticatedAt),
      now,
      ...(input.metadata ? { metadata: input.metadata } : {}),
    })
  })
}

export async function changeCurrentAccountPasswordByToken(
  runtime: AuthServiceRuntime,
  input: ChangeCurrentAccountPasswordByTokenInput,
): Promise<Credential> {
  return runtime.transaction.run(async () => {
    const now = input.now ?? runtime.clock.now()
    const { user } = await resolveSessionContext(runtime, {
      sessionToken: input.sessionToken,
      now,
    })

    return changePassword(runtime, {
      userId: user.id,
      currentPassword: input.currentPassword,
      newPassword: input.newPassword,
      ...optionalProp('reAuthenticatedAt', input.reAuthenticatedAt),
      now,
      ...(input.metadata ? { metadata: input.metadata } : {}),
    })
  })
}
