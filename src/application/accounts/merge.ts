import type { AuthServiceRuntime } from '../runtime.js'
import { PolicyDenialReason } from './shared.js'
import {
  buildMergeAuditMetadata,
  createMergeDeniedAudit,
  createMergeResult,
  disableSourceUser,
  findCredentialConflictTypes,
  isAlreadyMergedSource,
  loadMergeState,
  moveCredentialsToTarget,
  moveIdentitiesToTarget,
  revokeActiveSessions,
  type MergeDeniedAudit,
  type MergeState,
} from './merge-support.js'
import { audit } from '../support.js'
import { normalizeMetadataRecord } from '../metadata.js'
import { resolveSessionContext } from '../session-context.js'
import type { MergeAccountsInput, MergeResult } from '../../domain/types.js'
import { AuditEventType, isActiveUser } from '../../domain/types.js'
import { UniAuthError, UniAuthErrorCode, invalidInput } from '../../errors.js'

export async function mergeAccounts(
  runtime: AuthServiceRuntime,
  input: MergeAccountsInput,
): Promise<MergeResult> {
  const now = input.now ?? runtime.clock.now()
  const metadata = normalizeMergeMetadata(input.metadata)
  let deniedAudit: MergeDeniedAudit | undefined

  try {
    return await runtime.transaction.run(async () => {
      const state = await loadMergeState(runtime, input, now)
      const alreadyMergedResult = await resolveAlreadyMergedResult(runtime, state, now, metadata)

      if (alreadyMergedResult) {
        return alreadyMergedResult
      }

      await ensureSourceOwnership(runtime, input, now)

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
          requestMetadata: metadata,
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
          requestMetadata: metadata,
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

function normalizeMergeMetadata(
  metadata: Record<string, unknown> | undefined,
): Record<string, unknown> | undefined {
  return normalizeMetadataRecord(metadata, 'Merge metadata')
}

async function resolveAlreadyMergedResult(
  runtime: AuthServiceRuntime,
  state: MergeState,
  now: Date,
  requestMetadata: Record<string, unknown> | undefined,
): Promise<MergeResult | undefined> {
  if (isActiveUser(state.sourceUser)) {
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

async function ensureSourceOwnership(
  runtime: AuthServiceRuntime,
  input: MergeAccountsInput,
  now: Date,
): Promise<void> {
  if (!input.sourceSessionToken) {
    throw invalidInput('Source session token is required for account merge.')
  }

  const { user } = await resolveSessionContext(runtime, {
    sessionToken: input.sourceSessionToken,
    now,
  })

  if (user.id !== input.sourceUserId) {
    throw new UniAuthError(UniAuthErrorCode.SessionNotFound, 'Session was not found.')
  }
}
