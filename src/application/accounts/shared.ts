import type { AuthServiceRuntime } from '../runtime.js'
import type { AuthIdentity, UserId } from '../../domain/types.js'
import { isActiveIdentity } from '../../domain/types.js'

export const PolicyDenialReason = {
  IdentityAlreadyLinked: 'identity-already-linked',
  LinkDenied: 'link-denied',
  UnlinkDenied: 'unlink-denied',
  MergeDenied: 'merge-denied',
  MergeCredentialConflict: 'merge-credential-conflict',
} as const

export async function listActiveIdentitiesForUser(
  runtime: AuthServiceRuntime,
  userId: UserId,
): Promise<readonly AuthIdentity[]> {
  return (await runtime.repos.identityRepo.listByUserId(userId)).filter(isActiveIdentity)
}
