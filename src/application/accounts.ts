import type { AuthServiceRuntime } from './runtime.js'
import { optionalProp } from './optional.js'
import { createIdentityFromAssertion, resolveAssertion } from './sign-in.js'
import {
  ensureReAuth,
  audit,
  getActiveIdentity,
  getActiveUser,
  isActiveIdentity,
} from './support.js'
import type {
  AuthIdentity,
  IdentityId,
  LinkInput,
  LinkResult,
  MergeAccountsInput,
  MergeResult,
  UnlinkInput,
  UserId,
} from '../domain/types.js'
import { AuthIdentityStatus, SessionStatus } from '../domain/types.js'
import { UniAuthError, UniAuthErrorCode, invalidInput } from '../errors.js'

export async function link(runtime: AuthServiceRuntime, input: LinkInput): Promise<LinkResult> {
  return runtime.transaction.run(async () => {
    const now = input.now ?? runtime.clock.now()
    const user = await getActiveUser(runtime, input.userId)
    await ensureReAuth(runtime, 'link', user.id, input.reAuthenticatedAt, now)

    const assertion = await resolveAssertion(runtime, input)
    const exactIdentity = await runtime.repos.identityRepo.findByProviderUserId(
      assertion.provider,
      assertion.providerUserId,
    )

    if (exactIdentity && isActiveIdentity(exactIdentity)) {
      if (exactIdentity.userId === user.id) {
        return { user, identity: exactIdentity, linked: false }
      }

      await audit(runtime, 'auth.policy_denied', now, {
        userId: user.id,
        identityId: exactIdentity.id,
        metadata: { reason: 'identity-already-linked' },
      })
      throw new UniAuthError(UniAuthErrorCode.IdentityAlreadyLinked, 'Identity cannot be linked.')
    }

    const identity = await createIdentityFromAssertion(runtime, user, assertion, now)
    await audit(runtime, 'auth.identity_linked', now, {
      userId: user.id,
      identityId: identity.id,
      ...optionalProp('metadata', input.metadata),
    })

    return { user, identity, linked: true }
  })
}

export async function unlink(runtime: AuthServiceRuntime, input: UnlinkInput): Promise<void> {
  await runtime.transaction.run(async () => {
    const now = input.now ?? runtime.clock.now()
    const user = await getActiveUser(runtime, input.userId)
    await ensureReAuth(runtime, 'unlink', user.id, input.reAuthenticatedAt, now)

    const identity = await getActiveIdentity(runtime, input.identityId)

    if (identity.userId !== user.id) {
      throw new UniAuthError(UniAuthErrorCode.IdentityNotFound, 'Identity was not found.')
    }

    const activeIdentities = (await runtime.repos.identityRepo.listByUserId(user.id)).filter(
      isActiveIdentity,
    )
    const allowed = await runtime.policy.canUnlinkIdentity({
      user,
      identity,
      activeIdentityCount: activeIdentities.length,
    })

    if (!allowed) {
      await audit(runtime, 'auth.policy_denied', now, {
        userId: user.id,
        identityId: identity.id,
        metadata: { reason: 'unlink-denied' },
      })
      const code =
        activeIdentities.length <= 1 ? UniAuthErrorCode.LastIdentity : UniAuthErrorCode.PolicyDenied
      const message =
        activeIdentities.length <= 1
          ? 'Cannot unlink the last active identity.'
          : 'Auth policy denied this action.'
      throw new UniAuthError(code, message)
    }

    await runtime.repos.identityRepo.update(identity.id, {
      status: AuthIdentityStatus.Disabled,
      disabledAt: now,
      updatedAt: now,
    })
    await audit(runtime, 'auth.identity_unlinked', now, {
      userId: user.id,
      identityId: identity.id,
      ...optionalProp('metadata', input.metadata),
    })
  })
}

export async function mergeAccounts(
  runtime: AuthServiceRuntime,
  input: MergeAccountsInput,
): Promise<MergeResult> {
  return runtime.transaction.run(async () => {
    const now = input.now ?? runtime.clock.now()
    const sourceUser = await getActiveUser(runtime, input.sourceUserId)
    const targetUser = await getActiveUser(runtime, input.targetUserId)

    if (sourceUser.id === targetUser.id) {
      throw invalidInput('Source and target users must be different.')
    }

    await ensureReAuth(runtime, 'mergeAccounts', targetUser.id, input.reAuthenticatedAt, now)

    const sourceIdentities = (await runtime.repos.identityRepo.listByUserId(sourceUser.id)).filter(
      isActiveIdentity,
    )
    const allowed = await runtime.policy.canMergeUsers({
      sourceUser,
      targetUser,
      sourceIdentityCount: sourceIdentities.length,
    })

    if (!allowed) {
      await audit(runtime, 'auth.policy_denied', now, {
        userId: targetUser.id,
        metadata: { reason: 'merge-denied', sourceUserId: sourceUser.id },
      })
      throw new UniAuthError(UniAuthErrorCode.PolicyDenied, 'Auth policy denied this action.')
    }

    const movedIdentityIds: IdentityId[] = []

    for (const identity of sourceIdentities) {
      await runtime.repos.identityRepo.update(identity.id, {
        userId: targetUser.id,
        updatedAt: now,
      })
      movedIdentityIds.push(identity.id)
    }

    const disabledSourceUser = await runtime.repos.userRepo.update(sourceUser.id, {
      disabledAt: now,
      updatedAt: now,
    })

    const sourceSessions = await runtime.repos.sessionRepo.listByUserId(sourceUser.id)

    for (const session of sourceSessions) {
      if (session.status === SessionStatus.Active) {
        await runtime.repos.sessionRepo.update(session.id, {
          status: SessionStatus.Revoked,
          revokedAt: now,
        })
      }
    }

    await audit(runtime, 'auth.accounts_merged', now, {
      userId: targetUser.id,
      metadata: { sourceUserId: sourceUser.id, movedIdentityIds },
    })

    return {
      sourceUser: disabledSourceUser,
      targetUser,
      movedIdentityIds,
    }
  })
}

export async function getUserIdentities(
  runtime: AuthServiceRuntime,
  userId: UserId,
): Promise<readonly AuthIdentity[]> {
  await getActiveUser(runtime, userId)
  return runtime.repos.identityRepo.listByUserId(userId)
}
