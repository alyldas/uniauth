import { optionalProp } from '../optional.js'
import { normalizeMetadataRecord } from '../metadata.js'
import { AuthPolicyAction } from '../policy.js'
import type { AuthServiceRuntime } from '../runtime.js'
import { listActiveIdentitiesForUser, PolicyDenialReason } from './shared.js'
import { audit, ensureReAuth, getActiveIdentity, getActiveUser } from '../support.js'
import type { UnlinkInput } from '../../domain/types.js'
import { AuditEventType, AuthIdentityStatus } from '../../domain/types.js'
import { UniAuthError, UniAuthErrorCode } from '../../errors.js'

export async function unlink(runtime: AuthServiceRuntime, input: UnlinkInput): Promise<void> {
  await runtime.transaction.run(async () => {
    const now = input.now ?? runtime.clock.now()
    const metadata = normalizeUnlinkMetadata(input.metadata)
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
      ...optionalProp('metadata', metadata),
    })
  })
}

function normalizeUnlinkMetadata(
  metadata: Record<string, unknown> | undefined,
): Record<string, unknown> | undefined {
  return normalizeMetadataRecord(metadata, 'Unlink metadata')
}
