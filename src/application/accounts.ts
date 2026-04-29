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
  Session,
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

interface MergeDeniedAudit {
  readonly userId: UserId
  readonly metadata: Record<string, unknown>
}

interface MergeState {
  readonly sourceUser: User
  readonly targetUser: User
  readonly sourceIdentities: readonly AuthIdentity[]
  readonly targetIdentities: readonly AuthIdentity[]
  readonly sourceCredentials: readonly Credential[]
  readonly targetCredentials: readonly Credential[]
  readonly sourceSessions: readonly Session[]
}

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

    const activeIdentities = await listActiveIdentitiesForUser(runtime, user.id)
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
  let deniedAudit: MergeDeniedAudit | undefined

  try {
    return await runtime.transaction.run(async () => {
      const state = await loadMergeState(runtime, input, now)
      const alreadyMergedResult = await resolveAlreadyMergedResult(
        runtime,
        state,
        now,
        input.metadata,
      )

      if (alreadyMergedResult) {
        return alreadyMergedResult
      }

      const mergeAllowed = await runtime.policy.canMergeUsers({
        sourceUser: state.sourceUser,
        targetUser: state.targetUser,
        sourceIdentityCount: state.sourceIdentities.length,
        sourceIdentities: state.sourceIdentities,
        targetIdentities: state.targetIdentities,
      })

      if (!mergeAllowed) {
        deniedAudit = createMergeDeniedAudit({
          reason: PolicyDenialReason.MergeDenied,
          targetUserId: state.targetUser.id,
          sourceUserId: state.sourceUser.id,
        })
        throw new UniAuthError(UniAuthErrorCode.PolicyDenied, 'Auth policy denied this action.')
      }

      const conflictingCredentialTypes = findCredentialConflictTypes(
        state.sourceCredentials,
        state.targetCredentials,
      )

      if (conflictingCredentialTypes.length > 0) {
        deniedAudit = createMergeDeniedAudit({
          reason: PolicyDenialReason.MergeCredentialConflict,
          targetUserId: state.targetUser.id,
          sourceUserId: state.sourceUser.id,
          requestMetadata: input.metadata,
          metadata: { credentialTypes: conflictingCredentialTypes },
        })
        throw new UniAuthError(
          UniAuthErrorCode.CredentialAlreadyExists,
          'Credential already exists.',
        )
      }

      const movedIdentityIds = await moveIdentitiesToTarget(
        runtime,
        state.sourceIdentities,
        state.targetUser.id,
        now,
      )
      const movedCredentialIds = await moveCredentialsToTarget(
        runtime,
        state.sourceCredentials,
        state.targetUser.id,
        now,
      )
      const disabledSourceUser = await disableSourceUser(runtime, state.sourceUser.id, now)
      const revokedSessionIds = await revokeActiveSessions(runtime, state.sourceSessions, now)
      const result = createMergeResult({
        sourceUser: disabledSourceUser,
        targetUser: state.targetUser,
        movedIdentityIds,
        movedCredentialIds,
        revokedSessionIds,
      })

      await audit(runtime, AuditEventType.AccountsMerged, now, {
        userId: state.targetUser.id,
        metadata: buildMergeAuditMetadata({
          decision: 'merged',
          sourceUserId: state.sourceUser.id,
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

async function loadMergeState(
  runtime: AuthServiceRuntime,
  input: MergeAccountsInput,
  now: Date,
): Promise<MergeState> {
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

  const [sourceIdentities, targetIdentities, sourceCredentials, targetCredentials, sourceSessions] =
    await Promise.all([
      listActiveIdentitiesForUser(runtime, sourceUser.id),
      listActiveIdentitiesForUser(runtime, targetUser.id),
      runtime.repos.credentialRepo.listByUserId(sourceUser.id),
      runtime.repos.credentialRepo.listByUserId(targetUser.id),
      runtime.repos.sessionRepo.listByUserId(sourceUser.id),
    ])

  return {
    sourceUser,
    targetUser,
    sourceIdentities,
    targetIdentities,
    sourceCredentials,
    targetCredentials,
    sourceSessions,
  }
}

async function resolveAlreadyMergedResult(
  runtime: AuthServiceRuntime,
  state: MergeState,
  now: Date,
  requestMetadata: Record<string, unknown> | undefined,
): Promise<MergeResult | undefined> {
  if (!state.sourceUser.disabledAt) {
    return undefined
  }

  if (
    !isAlreadyMergedSource(state.sourceIdentities, state.sourceCredentials, state.sourceSessions)
  ) {
    throw new UniAuthError(UniAuthErrorCode.UserNotFound, 'User was not found.')
  }

  const result = createMergeResult({
    sourceUser: state.sourceUser,
    targetUser: state.targetUser,
  })

  await audit(runtime, AuditEventType.AccountsMerged, now, {
    userId: state.targetUser.id,
    metadata: buildMergeAuditMetadata({
      decision: 'already-merged',
      sourceUserId: state.sourceUser.id,
      result,
      requestMetadata,
    }),
  })

  return result
}

async function moveIdentitiesToTarget(
  runtime: AuthServiceRuntime,
  identities: readonly AuthIdentity[],
  targetUserId: UserId,
  now: Date,
): Promise<readonly IdentityId[]> {
  const movedIdentityIds: IdentityId[] = []

  for (const identity of identities) {
    await runtime.repos.identityRepo.update(identity.id, {
      userId: targetUserId,
      updatedAt: now,
    })
    movedIdentityIds.push(identity.id)
  }

  return movedIdentityIds
}

async function moveCredentialsToTarget(
  runtime: AuthServiceRuntime,
  credentials: readonly Credential[],
  targetUserId: UserId,
  now: Date,
): Promise<readonly CredentialId[]> {
  const movedCredentialIds: CredentialId[] = []

  for (const credential of credentials) {
    await runtime.repos.credentialRepo.update(credential.id, {
      userId: targetUserId,
      updatedAt: now,
    })
    movedCredentialIds.push(credential.id)
  }

  return movedCredentialIds
}

async function disableSourceUser(
  runtime: AuthServiceRuntime,
  sourceUserId: UserId,
  now: Date,
): Promise<User> {
  return runtime.repos.userRepo.update(sourceUserId, {
    disabledAt: now,
    updatedAt: now,
  })
}

async function revokeActiveSessions(
  runtime: AuthServiceRuntime,
  sessions: readonly Session[],
  now: Date,
): Promise<readonly SessionId[]> {
  const revokedSessionIds: SessionId[] = []

  for (const session of sessions) {
    if (session.status !== SessionStatus.Active) {
      continue
    }

    await runtime.repos.sessionRepo.update(session.id, {
      status: SessionStatus.Revoked,
      revokedAt: now,
    })
    revokedSessionIds.push(session.id)
  }

  return revokedSessionIds
}

async function listActiveIdentitiesForUser(
  runtime: AuthServiceRuntime,
  userId: UserId,
): Promise<readonly AuthIdentity[]> {
  return (await runtime.repos.identityRepo.listByUserId(userId)).filter(isActiveIdentity)
}

function createMergeDeniedAudit(input: {
  readonly reason:
    | typeof PolicyDenialReason.MergeDenied
    | typeof PolicyDenialReason.MergeCredentialConflict
  readonly targetUserId: UserId
  readonly sourceUserId: UserId
  readonly metadata?: Record<string, unknown> | undefined
  readonly requestMetadata?: Record<string, unknown> | undefined
}): MergeDeniedAudit {
  return {
    userId: input.targetUserId,
    metadata: {
      ...input.metadata,
      reason: input.reason,
      sourceUserId: input.sourceUserId,
      ...optionalProp('requestMetadata', input.requestMetadata),
    },
  }
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
