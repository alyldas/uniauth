import type { AuthServiceRuntime } from '../runtime.js'
import { isActiveIdentity } from '../support.js'
import type { AuthIdentity, ProviderIdentityAssertion, User } from '../../domain/types.js'

export async function findAutoLinkTarget(
  runtime: AuthServiceRuntime,
  assertion: ProviderIdentityAssertion,
): Promise<User | undefined> {
  const identities = await collectCandidateIdentities(runtime, assertion)
  const userIds = [...new Set(identities.map((identity) => identity.userId))]

  if (userIds.length !== 1) {
    return undefined
  }

  const targetUser = await runtime.repos.userRepo.findById(userIds[0]!)

  if (!targetUser || targetUser.disabledAt) {
    return undefined
  }

  const allowed = await runtime.policy.canAutoLink({
    assertion,
    targetUser,
    existingIdentities: identities,
  })

  return allowed ? targetUser : undefined
}

async function collectCandidateIdentities(
  runtime: AuthServiceRuntime,
  assertion: ProviderIdentityAssertion,
): Promise<AuthIdentity[]> {
  const candidateIdentities = new Map<string, AuthIdentity>()

  if (assertion.email && assertion.emailVerified === true) {
    for (const identity of await runtime.repos.identityRepo.findByVerifiedEmail(assertion.email)) {
      if (isActiveIdentity(identity)) {
        candidateIdentities.set(identity.id, identity)
      }
    }
  }

  if (assertion.phone && assertion.phoneVerified === true) {
    for (const identity of await runtime.repos.identityRepo.findByVerifiedPhone(assertion.phone)) {
      if (isActiveIdentity(identity)) {
        candidateIdentities.set(identity.id, identity)
      }
    }
  }

  return [...candidateIdentities.values()]
}
