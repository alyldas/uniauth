import { optionalProp } from './optional.js'
import type { AuthServiceRuntime } from './runtime.js'
import { createSessionRecord } from './sessions.js'
import { audit, getActiveUser, isActiveIdentity } from './support.js'
import {
  AuthIdentityStatus,
  type AuthIdentity,
  type AuthResult,
  type FinishInput,
  type ProviderIdentityAssertion,
  type Session,
  type SignInInput,
  type User,
} from '../domain/types.js'
import { UniAuthError, UniAuthErrorCode, invalidInput } from '../errors.js'
import { normalizeEmail, normalizePhone } from '../utils/normalization.js'

type SignInMode = 'exact' | 'auto-link' | 'new-user'

interface SignInWithAssertionInput {
  readonly now: Date
  readonly sessionExpiresAt?: Date
  readonly metadata?: Record<string, unknown>
}

export async function signIn(runtime: AuthServiceRuntime, input: SignInInput): Promise<AuthResult> {
  return runtime.transaction.run(async () => {
    const now = input.now ?? runtime.clock.now()
    const assertion = await resolveAssertion(runtime, input)
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
    const session = await createSessionForSignIn(runtime, user, input)
    await auditSuccessfulSignIn(runtime, 'exact', input, user, exactIdentity, session)

    return {
      user,
      identity: exactIdentity,
      session,
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
    const session = await createSessionForSignIn(runtime, autoLinkTarget, input)
    await audit(runtime, 'auth.identity_linked', input.now, {
      userId: autoLinkTarget.id,
      identityId: identity.id,
      metadata: { mode: 'auto-link' },
    })
    await auditSuccessfulSignIn(runtime, 'auto-link', input, autoLinkTarget, identity, session)

    return {
      user: autoLinkTarget,
      identity,
      session,
      isNewUser: false,
      isNewIdentity: true,
    }
  }

  const user = await createUserFromAssertion(runtime, assertion, input.now)
  const identity = await createIdentityFromAssertion(runtime, user, assertion, input.now)
  const session = await createSessionForSignIn(runtime, user, input)
  await auditSuccessfulSignIn(runtime, 'new-user', input, user, identity, session)

  return {
    user,
    identity,
    session,
    isNewUser: true,
    isNewIdentity: true,
  }
}

async function createSessionForSignIn(
  runtime: AuthServiceRuntime,
  user: User,
  input: SignInWithAssertionInput,
): Promise<Session> {
  return createSessionRecord(runtime, {
    userId: user.id,
    now: input.now,
    ...optionalProp('expiresAt', input.sessionExpiresAt),
    ...optionalProp('metadata', input.metadata),
  })
}

async function auditSuccessfulSignIn(
  runtime: AuthServiceRuntime,
  mode: SignInMode,
  input: SignInWithAssertionInput,
  user: User,
  identity: AuthIdentity,
  session: Session,
): Promise<void> {
  await audit(runtime, 'auth.sign_in', input.now, {
    userId: user.id,
    identityId: identity.id,
    sessionId: session.id,
    metadata: { mode },
  })
}

export async function resolveAssertion(
  runtime: AuthServiceRuntime,
  input: {
    readonly assertion?: ProviderIdentityAssertion
    readonly provider?: string
    readonly finishInput?: FinishInput
  },
): Promise<ProviderIdentityAssertion> {
  if (input.assertion) {
    return normalizeAssertion(input.assertion)
  }

  if (!input.provider || !input.finishInput) {
    throw invalidInput('Either assertion or provider finish input is required.')
  }

  if (!runtime.providerRegistry) {
    throw new UniAuthError(UniAuthErrorCode.ProviderNotFound, 'Auth provider was not found.')
  }

  const provider = await runtime.providerRegistry.get(input.provider)

  if (!provider) {
    throw new UniAuthError(UniAuthErrorCode.ProviderNotFound, 'Auth provider was not found.')
  }

  return normalizeAssertion(await provider.finish(input.finishInput))
}

export function normalizeAssertion(
  assertion: Partial<ProviderIdentityAssertion>,
): ProviderIdentityAssertion {
  const provider = assertion.provider?.trim() ?? ''
  const providerUserId = assertion.providerUserId?.trim() ?? ''

  if (!provider || !providerUserId) {
    throw invalidInput('Provider and provider user id are required.')
  }

  const email = assertion.email ? normalizeEmail(assertion.email) : undefined
  const phone = assertion.phone ? normalizePhone(assertion.phone) : undefined
  const displayName = assertion.displayName?.trim() || undefined

  return {
    provider,
    providerUserId,
    ...(email
      ? {
          email,
          emailVerified: assertion.emailVerified === true,
        }
      : {}),
    ...(phone
      ? {
          phone,
          phoneVerified: assertion.phoneVerified === true,
        }
      : {}),
    ...optionalProp('displayName', displayName),
    ...optionalProp('metadata', assertion.metadata),
  }
}

async function findAutoLinkTarget(
  runtime: AuthServiceRuntime,
  assertion: ProviderIdentityAssertion,
): Promise<User | undefined> {
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

  const identities = [...candidateIdentities.values()]
  const userIds = [...new Set(identities.map((identity) => identity.userId))]

  if (userIds.length !== 1) {
    return undefined
  }

  const userId = userIds[0]

  if (!userId) {
    return undefined
  }

  const targetUser = await runtime.repos.userRepo.findById(userId)

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

export async function createUserFromAssertion(
  runtime: AuthServiceRuntime,
  assertion: ProviderIdentityAssertion,
  now: Date,
): Promise<User> {
  const user: User = {
    id: runtime.idGenerator.userId(),
    createdAt: now,
    updatedAt: now,
    ...optionalProp('displayName', assertion.displayName),
    ...(assertion.email && assertion.emailVerified === true ? { email: assertion.email } : {}),
    ...(assertion.phone && assertion.phoneVerified === true ? { phone: assertion.phone } : {}),
  }

  return runtime.repos.userRepo.create(user)
}

export async function createIdentityFromAssertion(
  runtime: AuthServiceRuntime,
  user: User,
  assertion: ProviderIdentityAssertion,
  now: Date,
): Promise<AuthIdentity> {
  const identity: AuthIdentity = {
    id: runtime.idGenerator.identityId(),
    userId: user.id,
    provider: assertion.provider,
    providerUserId: assertion.providerUserId,
    status: AuthIdentityStatus.Active,
    createdAt: now,
    updatedAt: now,
    ...(assertion.email
      ? { email: assertion.email, emailVerified: assertion.emailVerified === true }
      : {}),
    ...(assertion.phone
      ? { phone: assertion.phone, phoneVerified: assertion.phoneVerified === true }
      : {}),
    ...optionalProp('metadata', assertion.metadata),
  }

  return runtime.repos.identityRepo.create(identity)
}
