import { optionalProp } from './optional.js'
import { normalizeOtpTarget, type SupportedOtpChannel } from './otp-delivery.js'
import {
  cancelOtpChallenge,
  enforceOtpFinishRateLimit,
  findOtpChallengeRecord,
  resendOtpChallenge,
  startOtpChallenge,
} from './otp.js'
import type { AuthServiceRuntime } from './runtime.js'
import { resolveSessionContext } from './session-context.js'
import { audit, ensureReAuth } from './support.js'
import { consumeVerificationRecord } from './verifications.js'
import type {
  CancelCurrentAccountContactChangeInput,
  FinishCurrentAccountContactChangeInput,
  OtpChannel as OtpChannelType,
  ResendCurrentAccountContactChangeInput,
  SessionId,
  StartCurrentAccountContactChangeInput,
  StartOtpChallengeResult,
  User,
  UserId,
  Verification,
} from '../domain/types.js'
import {
  AuditEventType,
  AuthPolicyAction,
  OtpChannel,
  VerificationPurpose,
} from '../domain/types.js'
import { UniAuthError, UniAuthErrorCode, invalidInput, isUniAuthError } from '../errors.js'

const CurrentAccountContactField = {
  Email: 'email',
  Phone: 'phone',
} as const

const CURRENT_ACCOUNT_CONTACT_CHANGE_METADATA_KEY = 'currentAccountContactChange'

interface CurrentAccountContactChangeMetadata {
  readonly userId: string
  readonly sessionId: string
  readonly channel: SupportedOtpChannel
}

export async function startCurrentAccountContactChange(
  runtime: AuthServiceRuntime,
  input: StartCurrentAccountContactChangeInput,
): Promise<StartOtpChallengeResult> {
  const now = input.now ?? runtime.clock.now()
  const { session, user } = await resolveSessionContext(runtime, {
    sessionToken: input.sessionToken,
    now,
  })

  await ensureReAuth(runtime, AuthPolicyAction.UpdateContact, user.id, input.reAuthenticatedAt, now)
  const target = normalizeCurrentAccountContactTarget(runtime, input.channel, input.target)

  rejectUnchangedContact(user, input.channel, target)

  return startOtpChallenge(runtime, {
    purpose: VerificationPurpose.ContactChange,
    channel: input.channel,
    target,
    ...optionalProp('secret', input.secret),
    ...optionalProp('ttlSeconds', input.ttlSeconds),
    now,
    metadata: buildCurrentAccountContactChangeMetadata(
      user.id,
      session.id,
      input.channel,
      input.metadata,
    ),
  })
}

export async function resendCurrentAccountContactChange(
  runtime: AuthServiceRuntime,
  input: ResendCurrentAccountContactChangeInput,
): Promise<StartOtpChallengeResult> {
  const { actor, challenge } = await resolveCurrentAccountOwnedContactChangeChallenge(
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
    metadata: buildCurrentAccountContactChangeMetadata(
      actor.userId,
      actor.sessionId,
      challenge.channel,
      input.metadata,
    ),
  })
}

export async function cancelCurrentAccountContactChange(
  runtime: AuthServiceRuntime,
  input: CancelCurrentAccountContactChangeInput,
): Promise<Verification> {
  const { actor, challenge } = await resolveCurrentAccountOwnedContactChangeChallenge(
    runtime,
    input.sessionToken,
    input.verificationId,
    input.now,
  )

  return cancelOtpChallenge(runtime, {
    verificationId: challenge.verification.id,
    purpose: VerificationPurpose.ContactChange,
    channel: challenge.channel,
    now: actor.now,
    metadata: buildCurrentAccountContactChangeMetadata(
      actor.userId,
      actor.sessionId,
      challenge.channel,
      input.metadata,
    ),
  })
}

export async function finishCurrentAccountContactChange(
  runtime: AuthServiceRuntime,
  input: FinishCurrentAccountContactChangeInput,
): Promise<User> {
  const resolved = await resolveCurrentAccountOwnedContactChangeChallenge(
    runtime,
    input.sessionToken,
    input.verificationId,
    input.now,
  )
  await enforceOtpFinishRateLimit(runtime, resolved.challenge, resolved.actor.now)

  return runtime.transaction.run(async () => {
    const { actor, challenge } = await resolveCurrentAccountOwnedContactChangeChallenge(
      runtime,
      input.sessionToken,
      input.verificationId,
      resolved.actor.now,
    )
    const consumed = await consumeVerificationRecord(runtime, {
      verificationId: challenge.verification.id,
      secret: input.secret,
      now: actor.now,
    })
    const updated = await runtime.repos.userRepo.update(actor.userId, {
      [contactFieldFromChannel(challenge.channel)]: consumed.target,
      updatedAt: actor.now,
    })

    await audit(runtime, AuditEventType.AccountContactUpdated, actor.now, {
      userId: actor.userId,
      sessionId: actor.sessionId,
      metadata: {
        verificationId: consumed.id,
        channel: challenge.channel,
        changedFields: [contactFieldFromChannel(challenge.channel)],
        ...optionalProp('requestMetadata', input.metadata),
      },
    })

    return updated
  })
}

function normalizeCurrentAccountContactTarget(
  runtime: Pick<AuthServiceRuntime, 'normalizer'>,
  channel: OtpChannelType,
  target: string,
): string {
  if (channel !== OtpChannel.Email && channel !== OtpChannel.Phone) {
    throw invalidInput('Current account contact change channel is not supported.')
  }

  return normalizeOtpTarget(runtime, channel, target)
}

function rejectUnchangedContact(user: User, channel: OtpChannelType, target: string): void {
  if (channel === OtpChannel.Email && user.email === target) {
    throw invalidInput('Current account email already matches the requested target.')
  }

  if (channel === OtpChannel.Phone && user.phone === target) {
    throw invalidInput('Current account phone already matches the requested target.')
  }
}

function buildCurrentAccountContactChangeMetadata(
  userId: UserId,
  sessionId: SessionId,
  channel: SupportedOtpChannel,
  requestMetadata: Record<string, unknown> | undefined,
): Record<string, unknown> {
  return {
    [CURRENT_ACCOUNT_CONTACT_CHANGE_METADATA_KEY]: {
      userId,
      sessionId,
      channel,
    },
    ...optionalProp('requestMetadata', requestMetadata),
  }
}

async function resolveCurrentAccountOwnedContactChangeChallenge(
  runtime: AuthServiceRuntime,
  sessionToken: string,
  verificationId: Verification['id'],
  now: Date | undefined,
): Promise<{
  readonly actor: { readonly now: Date; readonly sessionId: SessionId; readonly userId: UserId }
  readonly challenge: {
    readonly verification: Verification
    readonly channel: SupportedOtpChannel
  }
}> {
  const resolvedNow = now ?? runtime.clock.now()
  const { session, user } = await resolveSessionContext(runtime, {
    sessionToken,
    now: resolvedNow,
  })
  const challenge = await getCurrentAccountContactChangeChallenge(runtime, verificationId)
  const metadata = readCurrentAccountContactChangeMetadata(challenge.verification.metadata)

  if (!metadata || metadata.userId !== user.id || metadata.channel !== challenge.channel) {
    throw new UniAuthError(UniAuthErrorCode.VerificationNotFound, 'Verification was not found.')
  }

  if (metadata.sessionId !== session.id) {
    throw new UniAuthError(UniAuthErrorCode.VerificationNotFound, 'Verification was not found.')
  }

  return {
    actor: { now: resolvedNow, sessionId: session.id, userId: user.id },
    challenge,
  }
}

async function getCurrentAccountContactChangeChallenge(
  runtime: AuthServiceRuntime,
  verificationId: Verification['id'],
): Promise<{
  readonly verification: Verification
  readonly channel: SupportedOtpChannel
}> {
  try {
    return await findOtpChallengeRecord(runtime, {
      verificationId,
      purpose: VerificationPurpose.ContactChange,
      context: 'current-account contact change',
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

function readCurrentAccountContactChangeMetadata(
  metadata: Record<string, unknown> | undefined,
): CurrentAccountContactChangeMetadata | undefined {
  const raw = metadata?.[CURRENT_ACCOUNT_CONTACT_CHANGE_METADATA_KEY]

  if (!raw || typeof raw !== 'object') {
    return undefined
  }

  const candidate = raw as Partial<CurrentAccountContactChangeMetadata>

  if (
    typeof candidate.userId !== 'string' ||
    typeof candidate.sessionId !== 'string' ||
    (candidate.channel !== OtpChannel.Email && candidate.channel !== OtpChannel.Phone)
  ) {
    return undefined
  }

  return {
    userId: candidate.userId,
    sessionId: candidate.sessionId,
    channel: candidate.channel,
  }
}

function contactFieldFromChannel(channel: SupportedOtpChannel): 'email' | 'phone' {
  return channel === OtpChannel.Email
    ? CurrentAccountContactField.Email
    : CurrentAccountContactField.Phone
}
