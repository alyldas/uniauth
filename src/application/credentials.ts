import type { AuthServiceRuntime } from './runtime.js'
import { getActiveUser } from './support.js'
import type { Credential, UserId } from '../domain/types.js'

export async function getUserCredentials(
  runtime: AuthServiceRuntime,
  userId: UserId,
): Promise<readonly Credential[]> {
  await getActiveUser(runtime, userId)
  return runtime.repos.credentialRepo.listByUserId(userId)
}
