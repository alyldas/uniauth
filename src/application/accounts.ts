import type { AuthServiceRuntime } from './runtime.js'
import { optionalProp } from './optional.js'
import { AuthPolicyAction } from './policy.js'
import { createIdentityFromAssertion, resolveAssertion } from './sign-in.js'
import {
  audit,
  ensureReAuth,
  getActiveIdentity,
  getActiveUser,
  isActiveIdentity,
} from './support.js'
import type {
  AuthIdentity,
  Credential,
  CredentialId,
  IdentityId,
  LinkInput,
  LinkResult,
  MergeAccountsInput,
  MergeResult,
  SessionId,
  UnlinkInput,
  UserId,
  User,
} from '../domain/types.js'
import { AuditEventType, AuthIdentityStatus, SessionStatus } from '../domain/types.js'
import { UniAuthError, UniAuthErrorCode, invalidInput } from '../errors.js'

const PolicyDenialReason = {
  IdentityAlreadyLinked: 'identity-already-linked',
  LinkDenied: 'link-denied',
  UnlinkDenied: 'unlink-denied',
  MergeDenied: 'merge-denied',
  MergeCredentialConflict: 'merge-credential-conflict',
} as const

export async function link(runtime: AuthServiceRuntime, input: LinkInput): Promise<LinkResult> {
  return runtime.transaction.run(async () => {
    const now = input.now ?? runtime.clock.now()
    const user = await getActiveUser(runtime, input.userId)
    await ensureReAuth(runtime, AuthPolicyAction.Link, user.id, input.reAuthenticatedAt, now)

    const assertion = await resolveAssertion(runtime, input)
    const exactIdentity = await runtime.repos.identityRepo.findByProviderUserId(
      assertion.provider,
      assertion.providerUserId,
    )

    if (exactIdentity && isActiveIdentity(exactIdentity)) {
      if (exactIdentity.userId === user.id) {
        return { user, identity: exactIdentity, linked: false }
      }

      await audit(runtime, AuditEventType.PolicyDenied, now, {
        userId: user.id,
        identityId: exactIdentity.id,
        metadata: { reason: PolicyDenialReason.IdentityAlreadyLinked },
      })
      throw new UniAuthError(UniAuthErrorCode.IdentityAlreadyLinked, 'Identity cannot be linked.')
    }

    const allowed =
      (await runtime.policy.canLinkIdentity?.({
        user,
        assertion,
      })) ?? true

    if (!allowed) {
      await audit(runtime, AuditEventType.PolicyDenied, now, {
        userId: user.id,
        metadata: { reason: PolicyDenialReason.LinkDenied, provider: assertion.provider },
      })
      throw new UniAuthError(UniAuthErrorCode.PolicyDenied, 'Auth policy denied this action.')
    }

    const identity = await createIdentityFromAssertion(runtime, user, assertion, now)
    await audit(runtime, AuditEventType.IdentityLinked, now, {
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
    await ensureReAuth(runtime, AuthPolicyAction.Unlink, user.id, input.reAuthenticatedAt, now)

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
      await audit(runtime, AuditEventType.PolicyDenied, now, {
        userId: user.id,
        identityId: identity.id,
        metadata: { reason: PolicyDenialReason.UnlinkDenied },
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
    await audit(runtime, AuditEventType.IdentityUnlinked, now, {
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
  const now = input.now ?? runtime.clock.now()
  let deniedAudit:
    | {
        readonly userId: UserId
        readonly metadata: Record<string, unknown>
      }
    | undefined

  try {
    return await runtime.transaction.run(async () => {
      const sourceUser = await runtime.repos.userRepo.findById(input.sourceUserId)
      const targetUser = await getActiveUser(runtime, input.targetUserId)

      if (!sourceUser) {
        throw new UniAuthError(UniAuthErrorCode.UserNotFound, 'User was not found.')
      }

      if (sourceUser.id === targetUser.id) {
        throw invalidInput('Source and target users must be different.')
      }

      await ensureReAuth(
        runtime,
        AuthPolicyAction.MergeAccounts,
        targetUser.id,
        input.reAuthenticatedAt,
        now,
      )

      const sourceIdentities = (
        await runtime.repos.identityRepo.listByUserId(sourceUser.id)
      ).filter(isActiveIdentity)
      const targetIdentities = (
        await runtime.repos.identityRepo.listByUserId(targetUser.id)
      ).filter(isActiveIdentity)
      const sourceCredentials = await runtime.repos.credentialRepo.listByUserId(sourceUser.id)
      const targetCredentials = await runtime.repos.credentialRepo.listByUserId(targetUser.id)
      const sourceSessions = await runtime.repos.sessionRepo.listByUserId(sourceUser.id)

      if (sourceUser.disabledAt) {
        if (!isAlreadyMergedSource(sourceIdentities, sourceCredentials, sourceSessions)) {
          throw new UniAuthError(UniAuthErrorCode.UserNotFound, 'User was not found.')
        }

        const result = createMergeResult({
          sourceUser,
          targetUser,
        })

        await audit(runtime, AuditEventType.AccountsMerged, now, {
          userId: targetUser.id,
          metadata: buildMergeAuditMetadata({
            decision: 'already-merged',
            sourceUserId: sourceUser.id,
            result,
            requestMetadata: input.metadata,
          }),
        })

        return result
      }

      const allowed = await runtime.policy.canMergeUsers({
        sourceUser,
        targetUser,
        sourceIdentityCount: sourceIdentities.length,
        sourceIdentities,
        targetIdentities,
      })

      if (!allowed) {
        deniedAudit = {
          userId: targetUser.id,
          metadata: { reason: PolicyDenialReason.MergeDenied, sourceUserId: sourceUser.id },
        }
        throw new UniAuthError(UniAuthErrorCode.PolicyDenied, 'Auth policy denied this action.')
      }

      const conflictingCredentialTypes = findCredentialConflictTypes(
        sourceCredentials,
        targetCredentials,
      )

      if (conflictingCredentialTypes.length > 0) {
        deniedAudit = {
          userId: targetUser.id,
          metadata: {
            reason: PolicyDenialReason.MergeCredentialConflict,
            sourceUserId: sourceUser.id,
            credentialTypes: conflictingCredentialTypes,
            ...optionalProp('requestMetadata', input.metadata),
          },
        }
        throw new UniAuthError(
          UniAuthErrorCode.CredentialAlreadyExists,
          'Credential already exists.',
        )
      }

      const movedIdentityIds: IdentityId[] = []
      const movedCredentialIds: CredentialId[] = []
      const revokedSessionIds: SessionId[] = []

      for (const identity of sourceIdentities) {
        await runtime.repos.identityRepo.update(identity.id, {
          userId: targetUser.id,
          updatedAt: now,
        })
        movedIdentityIds.push(identity.id)
      }

      for (const credential of sourceCredentials) {
        await runtime.repos.credentialRepo.update(credential.id, {
          userId: targetUser.id,
          updatedAt: now,
        })
        movedCredentialIds.push(credential.id)
      }

      const disabledSourceUser = await runtime.repos.userRepo.update(sourceUser.id, {
        disabledAt: now,
        updatedAt: now,
      })

      for (const session of sourceSessions) {
        if (session.status === SessionStatus.Active) {
          await runtime.repos.sessionRepo.update(session.id, {
            status: SessionStatus.Revoked,
            revokedAt: now,
          })
          revokedSessionIds.push(session.id)
        }
      }

      const result = createMergeResult({
        sourceUser: disabledSourceUser,
        targetUser,
        movedIdentityIds,
        movedCredentialIds,
        revokedSessionIds,
      })

      await audit(runtime, AuditEventType.AccountsMerged, now, {
        userId: targetUser.id,
        metadata: buildMergeAuditMetadata({
          decision: 'merged',
          sourceUserId: sourceUser.id,
          result,
          requestMetadata: input.metadata,
        }),
      })

      return result
    })
  } catch (error) {
    if (deniedAudit) {
      await audit(runtime, AuditEventType.PolicyDenied, now, deniedAudit)
    }

    throw error
  }
}

export async function getUserIdentities(
  runtime: AuthServiceRuntime,
  userId: UserId,
): Promise<readonly AuthIdentity[]> {
  await getActiveUser(runtime, userId)
  return runtime.repos.identityRepo.listByUserId(userId)
}

function findCredentialConflictTypes(
  sourceCredentials: readonly Credential[],
  targetCredentials: readonly Credential[],
): readonly Credential['type'][] {
  const targetTypes = new Set(targetCredentials.map((credential) => credential.type))
  const conflicts = new Set<Credential['type']>()

  for (const credential of sourceCredentials) {
    if (targetTypes.has(credential.type)) {
      conflicts.add(credential.type)
    }
  }

  return [...conflicts]
}

function isAlreadyMergedSource(
  activeSourceIdentities: readonly AuthIdentity[],
  sourceCredentials: readonly Credential[],
  sourceSessions: readonly { readonly status: SessionStatus }[],
): boolean {
  return (
    activeSourceIdentities.length === 0 &&
    sourceCredentials.length === 0 &&
    sourceSessions.every((session) => session.status !== SessionStatus.Active)
  )
}

function createMergeResult(input: {
  readonly sourceUser: User
  readonly targetUser: User
  readonly movedIdentityIds?: readonly IdentityId[]
  readonly movedCredentialIds?: readonly CredentialId[]
  readonly revokedSessionIds?: readonly SessionId[]
}): MergeResult {
  return {
    sourceUser: input.sourceUser,
    targetUser: input.targetUser,
    movedIdentityIds: input.movedIdentityIds ?? [],
    movedCredentialIds: input.movedCredentialIds ?? [],
    revokedSessionIds: input.revokedSessionIds ?? [],
  }
}

function buildMergeAuditMetadata(input: {
  readonly decision: 'merged' | 'already-merged'
  readonly sourceUserId: UserId
  readonly result: MergeResult
  readonly requestMetadata: Record<string, unknown> | undefined
}): Record<string, unknown> {
  return {
    decision: input.decision,
    sourceUserId: input.sourceUserId,
    movedIdentityIds: [...input.result.movedIdentityIds],
    movedCredentialIds: [...input.result.movedCredentialIds],
    revokedSessionIds: [...input.result.revokedSessionIds],
    ...optionalProp('requestMetadata', input.requestMetadata),
  }
}
