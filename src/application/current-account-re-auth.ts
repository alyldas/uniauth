import { listActiveIdentitiesForUser } from './accounts/shared.js'
import {
  buildCurrentAccountOtpReAuthMetadata,
  readCurrentAccountOtpReAuthMetadata,
} from './current-account-re-auth-metadata.js'
import { optionalProp } from './optional.js'
import { normalizeOtpTarget, type SupportedOtpChannel } from './otp-delivery.js'
import {
  cancelOtpChallenge,
  enforceOtpFinishRateLimit,
  findOtpChallengeRecord,
  resendOtpChallenge,
  startOtpChallenge,
} from './otp.js'
import { consumeVerificationRecord } from './verifications.js'
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
  CurrentAccountOtpReAuthConfirmation,
  CurrentAccountReAuthAssertion,
  CurrentAccountReAuthStatus,
  FinishCurrentAccountOtpReAuthInput,
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
import { assertValidDate } from '../utils/time.js'

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
  validateReAuthMarker(input.reAuthenticatedAt, actor.now)

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

function validateReAuthMarker(reAuthenticatedAt: Date | undefined, now: Date): void {
  if (reAuthenticatedAt === undefined) {
    return
  }

  assertValidDate(reAuthenticatedAt, 'Re-authentication time is invalid.')

  if (reAuthenticatedAt.getTime() > now.getTime()) {
    throw invalidInput('Re-authentication time cannot be in the future.')
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
    metadata: buildCurrentAccountOtpReAuthMetadata(
      actor.userId,
      actor.sessionId,
      input.channel,
      input.metadata,
    ),
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
    metadata: buildCurrentAccountOtpReAuthMetadata(
      actor.userId,
      actor.sessionId,
      challenge.channel,
      input.metadata,
    ),
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
    metadata: buildCurrentAccountOtpReAuthMetadata(
      actor.userId,
      actor.sessionId,
      challenge.channel,
      input.metadata,
    ),
  })
}

export async function finishCurrentAccountOtpReAuth(
  runtime: AuthServiceRuntime,
  input: FinishCurrentAccountOtpReAuthInput,
): Promise<CurrentAccountOtpReAuthConfirmation> {
  const resolved = await resolveCurrentAccountOwnedOtpReAuthChallenge(
    runtime,
    input.sessionToken,
    input.verificationId,
    input.now,
  )
  await enforceOtpFinishRateLimit(runtime, resolved.challenge, resolved.actor.now)

  return runtime.transaction.run(async () => {
    const { actor, challenge } = await resolveCurrentAccountOwnedOtpReAuthChallenge(
      runtime,
      input.sessionToken,
      input.verificationId,
      resolved.actor.now,
    )
    await consumeVerificationRecord(runtime, {
      verificationId: challenge.verification.id,
      secret: input.secret,
      now: actor.now,
    })

    return {
      currentSessionId: actor.sessionId,
      userId: actor.userId,
      reAuthenticatedAt: actor.now,
    }
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
      currentSessionId: actor.sessionId,
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
  const metadata = readCurrentAccountOtpReAuthMetadata(challenge.verification.metadata)
  const identities = await listActiveIdentitiesForUser(runtime, actor.userId)
  const owned = identities.some((identity) =>
    currentAccountOwnsOtpReAuthTarget(
      runtime,
      identity,
      challenge.verification.target,
      challenge.channel,
    ),
  )

  if (
    !metadata ||
    metadata.userId !== actor.userId ||
    metadata.sessionId !== actor.sessionId ||
    metadata.channel !== challenge.channel ||
    !owned
  ) {
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
