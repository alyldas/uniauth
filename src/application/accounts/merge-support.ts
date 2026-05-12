import { normalizeMetadataRecord } from '../metadata.js'
import { optionalProp } from '../optional.js'
import { AuthPolicyAction } from '../policy.js'
import type { AuthServiceRuntime } from '../runtime.js'
import { listActiveIdentitiesForUser } from './shared.js'
import { ensureReAuth, getActiveUser } from '../support.js'
import type {
  AuthIdentity,
  Credential,
  CredentialId,
  IdentityId,
  MergeAccountsInput,
  MergeResult,
  Session,
  SessionId,
  User,
  UserId,
} from '../../domain/types.js'
import { SessionStatus, hasActiveSessionStatus } from '../../domain/types.js'
import { UniAuthError, UniAuthErrorCode, invalidInput } from '../../errors.js'

export interface MergeDeniedAudit {
  readonly userId: UserId
  readonly metadata: Record<string, unknown>
}

export interface MergeState {
  readonly sourceUser: User
  readonly targetUser: User
  readonly sourceIdentities: readonly AuthIdentity[]
  readonly targetIdentities: readonly AuthIdentity[]
  readonly sourceCredentials: readonly Credential[]
  readonly targetCredentials: readonly Credential[]
  readonly sourceSessions: readonly Session[]
}

export async function loadMergeState(
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

export async function moveIdentitiesToTarget(
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

export async function moveCredentialsToTarget(
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

export async function disableSourceUser(
  runtime: AuthServiceRuntime,
  sourceUserId: UserId,
  now: Date,
): Promise<User> {
  return runtime.repos.userRepo.update(sourceUserId, {
    disabledAt: now,
    updatedAt: now,
  })
}

export async function revokeActiveSessions(
  runtime: AuthServiceRuntime,
  sessions: readonly Session[],
  now: Date,
): Promise<readonly SessionId[]> {
  const revokedSessionIds: SessionId[] = []

  for (const session of sessions) {
    if (!hasActiveSessionStatus(session)) {
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

export function createMergeDeniedAudit(input: {
  readonly reason: 'merge-denied' | 'merge-credential-conflict'
  readonly targetUserId: UserId
  readonly sourceUserId: UserId
  readonly metadata?: Record<string, unknown> | undefined
  readonly requestMetadata?: Record<string, unknown> | undefined
}): MergeDeniedAudit {
  const requestMetadata = normalizeMergeRequestMetadata(input.requestMetadata)

  return {
    userId: input.targetUserId,
    metadata: {
      ...input.metadata,
      reason: input.reason,
      sourceUserId: input.sourceUserId,
      ...optionalProp('requestMetadata', requestMetadata),
    },
  }
}

export function findCredentialConflictTypes(
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

export function isAlreadyMergedSource(
  activeSourceIdentities: readonly AuthIdentity[],
  sourceCredentials: readonly Credential[],
  sourceSessions: readonly { readonly status: SessionStatus }[],
): boolean {
  return (
    activeSourceIdentities.length === 0 &&
    sourceCredentials.length === 0 &&
    sourceSessions.every((session) => !hasActiveSessionStatus(session))
  )
}

export function createMergeResult(input: {
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

export function buildMergeAuditMetadata(input: {
  readonly decision: 'merged' | 'already-merged'
  readonly sourceUserId: UserId
  readonly result: MergeResult
  readonly requestMetadata: Record<string, unknown> | undefined
}): Record<string, unknown> {
  const requestMetadata = normalizeMergeRequestMetadata(input.requestMetadata)

  return {
    decision: input.decision,
    sourceUserId: input.sourceUserId,
    movedIdentityIds: [...input.result.movedIdentityIds],
    movedCredentialIds: [...input.result.movedCredentialIds],
    revokedSessionIds: [...input.result.revokedSessionIds],
    ...optionalProp('requestMetadata', requestMetadata),
  }
}

function normalizeMergeRequestMetadata(
  metadata: Record<string, unknown> | undefined,
): Record<string, unknown> | undefined {
  return normalizeMetadataRecord(metadata, 'Merge request metadata')
}
