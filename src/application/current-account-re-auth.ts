import { listActiveIdentitiesForUser } from './accounts/shared.js'
import { optionalProp } from './optional.js'
import { normalizeOtpTarget, type SupportedOtpChannel } from './otp-delivery.js'
import {
  cancelOtpChallenge,
  findOtpChallengeRecord,
  resendOtpChallenge,
  startOtpChallenge,
} from './otp.js'
import {
  getPasswordHasher,
  findUsablePasswordIdentity,
  assertPassword,
} from './passwords/shared.js'
import { ensureReAuth } from './support.js'
import type { AuthServiceRuntime } from './runtime.js'
import { resolveSessionContext } from './session-context.js'
import type {
  AssertCurrentAccountReAuthInput,
  AuthIdentity,
  CancelCurrentAccountOtpReAuthInput,
  ConfirmCurrentAccountPasswordByTokenInput,
  CurrentAccountReAuthAssertion,
  CurrentAccountReAuthStatus,
  CurrentAccountPasswordReAuthConfirmation,
  GetCurrentAccountReAuthStatusInput,
  OtpChannel as OtpChannelType,
  ResendCurrentAccountOtpReAuthInput,
  SessionId,
  StartOtpChallengeResult,
  StartCurrentAccountOtpReAuthInput,
  UserId,
  Verification,
} from '../domain/types.js'
import { OtpChannel, VerificationPurpose } from '../domain/types.js'
import {
  UniAuthError,
  UniAuthErrorCode,
  invalidCredentials,
  invalidInput,
  isUniAuthError,
} from '../errors.js'

const CURRENT_ACCOUNT_RE_AUTH_TARGET_ERROR =
  'Identity cannot be used for current-account OTP re-auth.'

interface ResolvedCurrentAccountActor {
  readonly now: Date
  readonly sessionId: SessionId
  readonly userId: UserId
}

export async function getCurrentAccountReAuthStatus(
  runtime: AuthServiceRuntime,
  input: GetCurrentAccountReAuthStatusInput,
): Promise<CurrentAccountReAuthStatus> {
  const actor = await resolveCurrentAccountActor(runtime, input.sessionToken, input.now)

  return {
    currentSessionId: actor.sessionId,
    userId: actor.userId,
    action: input.action,
    required: await runtime.policy.requiresReAuth({
      action: input.action,
      userId: actor.userId,
      reAuthenticatedAt: input.reAuthenticatedAt,
      now: actor.now,
    }),
    checkedAt: actor.now,
    ...optionalProp('reAuthenticatedAt', input.reAuthenticatedAt),
  }
}

export async function assertCurrentAccountReAuth(
  runtime: AuthServiceRuntime,
  input: AssertCurrentAccountReAuthInput,
): Promise<CurrentAccountReAuthAssertion> {
  const actor = await resolveCurrentAccountActor(runtime, input.sessionToken, input.now)

  await ensureReAuth(runtime, input.action, actor.userId, input.reAuthenticatedAt, actor.now)

  return {
    currentSessionId: actor.sessionId,
    userId: actor.userId,
    action: input.action,
    checkedAt: actor.now,
    ...optionalProp('reAuthenticatedAt', input.reAuthenticatedAt),
  }
}

export async function startCurrentAccountOtpReAuth(
  runtime: AuthServiceRuntime,
  input: StartCurrentAccountOtpReAuthInput,
): Promise<StartOtpChallengeResult> {
  const actor = await resolveCurrentAccountActor(runtime, input.sessionToken, input.now)
  const identities = await listActiveIdentitiesForUser(runtime, actor.userId)
  const identity = identities.find((candidate) => candidate.id === input.identityId)

  if (!identity) {
    throw invalidInput(CURRENT_ACCOUNT_RE_AUTH_TARGET_ERROR)
  }

  const target = resolveCurrentAccountOtpReAuthTarget(runtime, identity, input.channel)

  return startOtpChallenge(runtime, {
    purpose: VerificationPurpose.ReAuth,
    channel: input.channel,
    target,
    ...optionalProp('secret', input.secret),
    ...optionalProp('ttlSeconds', input.ttlSeconds),
    now: actor.now,
    ...(input.metadata ? { metadata: input.metadata } : {}),
  })
}

export async function resendCurrentAccountOtpReAuth(
  runtime: AuthServiceRuntime,
  input: ResendCurrentAccountOtpReAuthInput,
): Promise<StartOtpChallengeResult> {
  const { actor, challenge } = await resolveCurrentAccountOwnedOtpReAuthChallenge(
    runtime,
    input.sessionToken,
    input.verificationId,
    input.now,
  )

  return resendOtpChallenge(runtime, {
    verificationId: challenge.verification.id,
    ...optionalProp('secret', input.secret),
    ...optionalProp('ttlSeconds', input.ttlSeconds),
    now: actor.now,
    ...(input.metadata ? { metadata: input.metadata } : {}),
  })
}

export async function cancelCurrentAccountOtpReAuth(
  runtime: AuthServiceRuntime,
  input: CancelCurrentAccountOtpReAuthInput,
): Promise<Verification> {
  const { actor, challenge } = await resolveCurrentAccountOwnedOtpReAuthChallenge(
    runtime,
    input.sessionToken,
    input.verificationId,
    input.now,
  )

  return cancelOtpChallenge(runtime, {
    verificationId: challenge.verification.id,
    purpose: VerificationPurpose.ReAuth,
    channel: challenge.channel,
    now: actor.now,
    ...(input.metadata ? { metadata: input.metadata } : {}),
  })
}

export async function confirmCurrentAccountPasswordByToken(
  runtime: AuthServiceRuntime,
  input: ConfirmCurrentAccountPasswordByTokenInput,
): Promise<CurrentAccountPasswordReAuthConfirmation> {
  return runtime.transaction.run(async () => {
    const actor = await resolveCurrentAccountActor(runtime, input.sessionToken, input.now)

    assertPassword(input.currentPassword)

    const credential = await runtime.repos.credentialRepo.findPasswordByUserId(actor.userId)

    if (!credential) {
      throw invalidCredentials()
    }

    const passwordHasher = getPasswordHasher(runtime)

    if (!(await passwordHasher.verify(input.currentPassword, credential.passwordHash))) {
      throw invalidCredentials()
    }

    await findUsablePasswordIdentity(runtime, credential, credential.subject)

    return {
      userId: actor.userId,
      reAuthenticatedAt: actor.now,
    }
  })
}

async function resolveCurrentAccountActor(
  runtime: AuthServiceRuntime,
  sessionToken: string,
  now: Date | undefined,
): Promise<ResolvedCurrentAccountActor> {
  const resolvedNow = now ?? runtime.clock.now()
  const { session, user } = await resolveSessionContext(runtime, {
    sessionToken,
    now: resolvedNow,
  })

  return {
    now: resolvedNow,
    sessionId: session.id,
    userId: user.id,
  }
}

function resolveCurrentAccountOtpReAuthTarget(
  runtime: Pick<AuthServiceRuntime, 'normalizer'>,
  identity: AuthIdentity,
  channel: OtpChannelType,
): string {
  if (channel === OtpChannel.Email && identity.email && identity.emailVerified) {
    return normalizeOtpTarget(runtime, channel, identity.email)
  }

  if (channel === OtpChannel.Phone && identity.phone && identity.phoneVerified) {
    return normalizeOtpTarget(runtime, channel, identity.phone)
  }

  throw invalidInput(CURRENT_ACCOUNT_RE_AUTH_TARGET_ERROR)
}

async function resolveCurrentAccountOwnedOtpReAuthChallenge(
  runtime: AuthServiceRuntime,
  sessionToken: string,
  verificationId: Verification['id'],
  now: Date | undefined,
): Promise<{
  readonly actor: ResolvedCurrentAccountActor
  readonly challenge: {
    readonly verification: Verification
    readonly channel: SupportedOtpChannel
  }
}> {
  const actor = await resolveCurrentAccountActor(runtime, sessionToken, now)
  const challenge = await getCurrentAccountOwnedOtpReAuthChallenge(runtime, verificationId)
  const identities = await listActiveIdentitiesForUser(runtime, actor.userId)
  const owned = identities.some((identity) =>
    currentAccountOwnsOtpReAuthTarget(
      runtime,
      identity,
      challenge.verification.target,
      challenge.channel,
    ),
  )

  if (!owned) {
    throw new UniAuthError(UniAuthErrorCode.VerificationNotFound, 'Verification was not found.')
  }

  return { actor, challenge }
}

async function getCurrentAccountOwnedOtpReAuthChallenge(
  runtime: AuthServiceRuntime,
  verificationId: Verification['id'],
): Promise<{
  readonly verification: Verification
  readonly channel: SupportedOtpChannel
}> {
  try {
    return await findOtpChallengeRecord(runtime, {
      verificationId,
      purpose: VerificationPurpose.ReAuth,
      context: 'current-account OTP re-auth',
    })
  } catch (error) {
    if (
      isUniAuthError(error) &&
      (error.code === UniAuthErrorCode.VerificationNotFound ||
        error.code === UniAuthErrorCode.InvalidInput)
    ) {
      throw new UniAuthError(UniAuthErrorCode.VerificationNotFound, 'Verification was not found.')
    }

    throw error
  }
}

function currentAccountOwnsOtpReAuthTarget(
  runtime: Pick<AuthServiceRuntime, 'normalizer'>,
  identity: AuthIdentity,
  target: string,
  channel: SupportedOtpChannel,
): boolean {
  try {
    return resolveCurrentAccountOtpReAuthTarget(runtime, identity, channel) === target
  } catch {
    return false
  }
}
