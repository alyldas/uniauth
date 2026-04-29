import type { AuthServiceRuntime } from './runtime.js'
import { getActiveUser } from './support.js'
import type { User, UserId } from '../domain/types.js'

export async function getUser(runtime: AuthServiceRuntime, userId: UserId): Promise<User> {
  return getActiveUser(runtime, userId)
}
