import type { AuthServiceRuntime } from '../runtime.js'
import { getActiveUser } from '../support.js'
import type { AuthIdentity, UserId } from '../../domain/types.js'

export async function getUserIdentities(
  runtime: AuthServiceRuntime,
  userId: UserId,
): Promise<readonly AuthIdentity[]> {
  await getActiveUser(runtime, userId)
  return runtime.repos.identityRepo.listByUserId(userId)
}
