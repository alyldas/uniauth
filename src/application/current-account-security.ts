import { getAccountSecuritySnapshotForUser } from './account-security.js'
import type { AuthServiceRuntime } from './runtime.js'
import { resolveSessionContext } from './session-context.js'
import { revokeStoredSession, revokeUserSessions } from './sessions.js'
import {
  type CurrentAccountSecuritySnapshot,
  type GetCurrentAccountSecuritySnapshotInput,
  type RevokeCurrentSessionByTokenInput,
  type RevokeOtherSessionsByTokenInput,
  type RevokeOtherSessionsByTokenResult,
} from '../domain/types.js'

export async function getCurrentAccountSecuritySnapshot(
  runtime: AuthServiceRuntime,
  input: GetCurrentAccountSecuritySnapshotInput,
): Promise<CurrentAccountSecuritySnapshot> {
  const { session, user } = await resolveSessionContext(runtime, input)
  const account = await getAccountSecuritySnapshotForUser(runtime, user)

  return {
    account,
    currentSessionId: session.id,
  }
}

export async function revokeCurrentSessionByToken(
  runtime: AuthServiceRuntime,
  input: RevokeCurrentSessionByTokenInput,
): Promise<void> {
  await runtime.transaction.run(async () => {
    const now = input.now ?? runtime.clock.now()
    const { session } = await resolveSessionContext(runtime, {
      sessionToken: input.sessionToken,
      now,
    })

    await revokeStoredSession(runtime, session.id, now)
  })
}

export async function revokeOtherSessionsByToken(
  runtime: AuthServiceRuntime,
  input: RevokeOtherSessionsByTokenInput,
): Promise<RevokeOtherSessionsByTokenResult> {
  return runtime.transaction.run(async () => {
    const now = input.now ?? runtime.clock.now()
    const { session, user } = await resolveSessionContext(runtime, {
      sessionToken: input.sessionToken,
      now,
    })
    const revoked = await revokeUserSessions(runtime, {
      userId: user.id,
      exceptSessionId: session.id,
      now,
    })

    return {
      ...revoked,
      currentSessionId: session.id,
    }
  })
}
