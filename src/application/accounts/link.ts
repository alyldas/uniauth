import { optionalProp } from '../optional.js'
import { AuthPolicyAction } from '../policy.js'
import type { AuthServiceRuntime } from '../runtime.js'
import { createIdentityFromAssertion, resolveAssertion } from '../sign-in.js'
import { PolicyDenialReason } from './shared.js'
import { audit, ensureReAuth, getActiveUser } from '../support.js'
import type { LinkInput, LinkResult } from '../../domain/types.js'
import { AuditEventType, isActiveIdentity } from '../../domain/types.js'
import { UniAuthError, UniAuthErrorCode } from '../../errors.js'

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
