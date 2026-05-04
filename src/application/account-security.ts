import type { AuthServiceRuntime } from './runtime.js'
import { getActiveUser } from './support.js'
import {
  toAccountSecuritySnapshot,
  type AccountSecuritySnapshot,
  type User,
  type UserId,
} from '../domain/types.js'

export async function getAccountSecuritySnapshot(
  runtime: AuthServiceRuntime,
  userId: UserId,
): Promise<AccountSecuritySnapshot> {
  const user = await getActiveUser(runtime, userId)
  return getAccountSecuritySnapshotForUser(runtime, user)
}

export async function getAccountSecuritySnapshotForUser(
  runtime: AuthServiceRuntime,
  user: User,
): Promise<AccountSecuritySnapshot> {
  const [identities, credentials, sessions] = await Promise.all([
    runtime.repos.identityRepo.listByUserId(user.id),
    runtime.repos.credentialRepo.listByUserId(user.id),
    runtime.repos.sessionRepo.listByUserId(user.id),
  ])

  return toAccountSecuritySnapshot({
    user,
    identities,
    credentials,
    sessions,
  })
}
