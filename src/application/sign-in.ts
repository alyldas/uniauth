import { optionalProp } from './optional.js'
import type { AuthServiceRuntime } from './runtime.js'
import { audit, enforceRateLimit, getActiveUser, isActiveIdentity } from './support.js'
import { findAutoLinkTarget } from './sign-in/auto-link.js'
import { resolveAssertion } from './sign-in/assertion.js'
import {
  auditSuccessfulSignIn,
  createIdentityFromAssertion,
  createSessionForSignIn,
  createUserFromAssertion,
  SignInAuditMode,
  type SignInWithAssertionInput,
} from './sign-in/materialize.js'
import {
  AuditEventType,
  type AuthResult,
  type ProviderIdentityAssertion,
  type SignInInput,
} from '../domain/types.js'
import { RateLimitAction, rateLimitKey } from '../ports.js'

export { findAutoLinkTarget } from './sign-in/auto-link.js'
export { normalizeAssertion, resolveAssertion } from './sign-in/assertion.js'
export { createIdentityFromAssertion, createUserFromAssertion } from './sign-in/materialize.js'

export async function signIn(runtime: AuthServiceRuntime, input: SignInInput): Promise<AuthResult> {
  const now = input.now ?? runtime.clock.now()
  const assertion = await resolveAssertion(runtime, input)

  await enforceRateLimit(runtime, {
    action: RateLimitAction.ProviderSignIn,
    key: rateLimitKey(assertion.provider, assertion.providerUserId),
    now,
    metadata: { provider: assertion.provider },
  })

  return runtime.transaction.run(async () => {
    return signInWithAssertion(runtime, assertion, {
      now,
      ...optionalProp('sessionExpiresAt', input.sessionExpiresAt),
      ...optionalProp('metadata', input.metadata),
    })
  })
}

export async function signInWithAssertion(
  runtime: AuthServiceRuntime,
  assertion: ProviderIdentityAssertion,
  input: SignInWithAssertionInput,
): Promise<AuthResult> {
  const exactIdentity = await runtime.repos.identityRepo.findByProviderUserId(
    assertion.provider,
    assertion.providerUserId,
  )

  if (exactIdentity && isActiveIdentity(exactIdentity)) {
    const user = await getActiveUser(runtime, exactIdentity.userId)
    const createdSession = await createSessionForSignIn(runtime, user, input)
    await auditSuccessfulSignIn(
      runtime,
      SignInAuditMode.Exact,
      input,
      user,
      exactIdentity,
      createdSession.session,
    )

    return {
      user,
      identity: exactIdentity,
      session: createdSession.session,
      sessionToken: createdSession.sessionToken,
      isNewUser: false,
      isNewIdentity: false,
    }
  }

  const autoLinkTarget = await findAutoLinkTarget(runtime, assertion)

  if (autoLinkTarget) {
    const identity = await createIdentityFromAssertion(
      runtime,
      autoLinkTarget,
      assertion,
      input.now,
    )
    const createdSession = await createSessionForSignIn(runtime, autoLinkTarget, input)
    await audit(runtime, AuditEventType.IdentityLinked, input.now, {
      userId: autoLinkTarget.id,
      identityId: identity.id,
      metadata: { mode: SignInAuditMode.AutoLink },
    })
    await auditSuccessfulSignIn(
      runtime,
      SignInAuditMode.AutoLink,
      input,
      autoLinkTarget,
      identity,
      createdSession.session,
    )

    return {
      user: autoLinkTarget,
      identity,
      session: createdSession.session,
      sessionToken: createdSession.sessionToken,
      isNewUser: false,
      isNewIdentity: true,
    }
  }

  const user = await createUserFromAssertion(runtime, assertion, input.now)
  const identity = await createIdentityFromAssertion(runtime, user, assertion, input.now)
  const createdSession = await createSessionForSignIn(runtime, user, input)
  await auditSuccessfulSignIn(
    runtime,
    SignInAuditMode.NewUser,
    input,
    user,
    identity,
    createdSession.session,
  )

  return {
    user,
    identity,
    session: createdSession.session,
    sessionToken: createdSession.sessionToken,
    isNewUser: true,
    isNewIdentity: true,
  }
}
