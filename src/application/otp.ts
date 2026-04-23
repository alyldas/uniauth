import type { AuthServiceRuntime } from './runtime.js'
import { getOtpDelivery, normalizeOtpTarget, type SupportedOtpChannel } from './otp-delivery.js'
import { optionalProp } from './optional.js'
import { normalizeAssertion, signInWithAssertion } from './sign-in.js'
import { enforceRateLimit, rateLimitKey } from './support.js'
import { consumeVerificationRecord, createVerificationRecord } from './verifications.js'
import type {
  AuthResult,
  FinishOtpChallengeInput,
  FinishOtpSignInInput,
  OtpChannel as OtpChannelType,
  ProviderIdentityAssertion,
  StartOtpChallengeInput,
  StartOtpChallengeResult,
  Verification,
} from '../domain/types.js'
import {
  EMAIL_OTP_PROVIDER_ID,
  OtpChannel,
  PHONE_OTP_PROVIDER_ID,
  VerificationPurpose,
} from '../domain/types.js'
import { UniAuthError, UniAuthErrorCode, invalidInput } from '../errors.js'
import { RateLimitAction, type OtpSecretGeneratorInput } from '../ports.js'
import { generateOtpSecret } from '../utils/secrets.js'

const DEFAULT_OTP_SECRET_LENGTH = 6
const MIN_OTP_SECRET_LENGTH = 4
const MAX_OTP_SECRET_LENGTH = 8

export async function startOtpChallenge(
  runtime: AuthServiceRuntime,
  input: StartOtpChallengeInput,
): Promise<StartOtpChallengeResult> {
  const now = input.now ?? runtime.clock.now()
  const target = normalizeOtpTarget(input.channel, input.target)
  const delivery = getOtpDelivery(runtime, input.channel)
  await enforceRateLimit(runtime, {
    action: RateLimitAction.OtpStart,
    key: rateLimitKey(input.channel, target),
    now,
    metadata: { channel: input.channel, purpose: input.purpose },
  })
  const secret = await resolveOtpSecret(runtime, {
    purpose: input.purpose,
    channel: input.channel,
    target,
    now,
    ...optionalProp('secret', input.secret),
  })

  const created = await runtime.transaction.run(async () => {
    return createVerificationRecord(runtime, {
      purpose: input.purpose,
      target,
      provider: delivery.provider,
      channel: input.channel,
      secret,
      ...optionalProp('ttlSeconds', input.ttlSeconds),
      now,
      ...optionalProp('metadata', input.metadata),
    })
  })

  await delivery.send(created)

  return {
    verificationId: created.verification.id,
    expiresAt: created.verification.expiresAt,
    delivery: input.channel,
  }
}

export async function finishOtpChallenge(
  runtime: AuthServiceRuntime,
  input: FinishOtpChallengeInput,
): Promise<Verification> {
  const now = input.now ?? runtime.clock.now()
  const challenge = await findOtpChallengeRecord(runtime, {
    verificationId: input.verificationId,
    ...optionalProp('purpose', input.purpose),
    ...optionalProp('channel', input.channel),
    context: 'OTP challenge',
  })

  await enforceOtpFinishRateLimit(runtime, challenge, now)

  return runtime.transaction.run(async () => {
    await findOtpChallengeRecord(runtime, {
      verificationId: input.verificationId,
      ...optionalProp('purpose', input.purpose),
      ...optionalProp('channel', input.channel),
      context: 'OTP challenge',
    })

    return consumeVerificationRecord(runtime, {
      verificationId: input.verificationId,
      secret: input.secret,
      now,
    })
  })
}

export async function finishOtpSignIn(
  runtime: AuthServiceRuntime,
  input: FinishOtpSignInInput,
): Promise<AuthResult> {
  const now = input.now ?? runtime.clock.now()
  const challenge = await findOtpChallengeRecord(runtime, {
    verificationId: input.verificationId,
    purpose: VerificationPurpose.SignIn,
    ...optionalProp('channel', input.channel),
    context: 'OTP sign-in',
  })

  await enforceOtpFinishRateLimit(runtime, challenge, now)

  return runtime.transaction.run(async () => {
    const currentChallenge = await findOtpChallengeRecord(runtime, {
      verificationId: input.verificationId,
      purpose: VerificationPurpose.SignIn,
      ...optionalProp('channel', input.channel),
      context: 'OTP sign-in',
    })
    const verification = await consumeVerificationRecord(runtime, {
      verificationId: input.verificationId,
      secret: input.secret,
      now,
    })

    return signInWithAssertion(
      runtime,
      assertionFromOtpVerification(verification, currentChallenge.channel),
      {
        now,
        ...optionalProp('sessionExpiresAt', input.sessionExpiresAt),
        ...optionalProp('metadata', input.metadata),
      },
    )
  })
}

async function findOtpChallengeRecord(
  runtime: AuthServiceRuntime,
  input: {
    readonly verificationId: Verification['id']
    readonly purpose?: VerificationPurpose
    readonly channel?: OtpChannelType
    readonly context: string
  },
): Promise<{ readonly verification: Verification; readonly channel: SupportedOtpChannel }> {
  const verification = await runtime.repos.verificationRepo.findById(input.verificationId)

  if (!verification) {
    throw new UniAuthError(UniAuthErrorCode.VerificationNotFound, 'Verification was not found.')
  }

  if (input.purpose && verification.purpose !== input.purpose) {
    throw invalidInput(`Verification cannot be used for ${input.context}.`)
  }

  const channel = otpChannelFromVerification(verification)

  if (!channel) {
    throw invalidInput(`Verification cannot be used for ${input.context}.`)
  }

  if (input.channel && channel !== input.channel) {
    throw invalidInput(`Verification cannot be used for ${input.context}.`)
  }

  return { verification, channel }
}

async function enforceOtpFinishRateLimit(
  runtime: AuthServiceRuntime,
  challenge: { readonly verification: Verification; readonly channel: SupportedOtpChannel },
  now: Date,
): Promise<void> {
  await enforceRateLimit(runtime, {
    action: RateLimitAction.OtpFinish,
    key: rateLimitKey(challenge.channel, challenge.verification.id),
    now,
    metadata: { channel: challenge.channel, purpose: challenge.verification.purpose },
  })
}

async function resolveOtpSecret(
  runtime: AuthServiceRuntime,
  input: OtpSecretGeneratorInput & { readonly secret?: string },
): Promise<string> {
  const secret =
    input.secret ??
    (runtime.otpSecretGenerator
      ? await runtime.otpSecretGenerator(input)
      : generateOtpSecret(getOtpSecretLength(runtime)))

  if (!secret) {
    throw invalidInput('OTP secret is required.')
  }

  return secret
}

function getOtpSecretLength(runtime: AuthServiceRuntime): number {
  const length = runtime.otpSecretLength ?? DEFAULT_OTP_SECRET_LENGTH

  if (
    !Number.isInteger(length) ||
    length < MIN_OTP_SECRET_LENGTH ||
    length > MAX_OTP_SECRET_LENGTH
  ) {
    throw invalidInput('OTP secret length must be an integer from 4 to 8.')
  }

  return length
}

function otpChannelFromVerification(verification: Verification): SupportedOtpChannel | undefined {
  const channel = verification.channel

  if (channel === OtpChannel.Email || channel === OtpChannel.Phone) {
    return channel
  }

  return undefined
}

function assertionFromOtpVerification(
  verification: Verification,
  channel: SupportedOtpChannel,
): ProviderIdentityAssertion {
  if (channel === OtpChannel.Email) {
    return normalizeAssertion({
      provider: EMAIL_OTP_PROVIDER_ID,
      providerUserId: verification.target,
      email: verification.target,
      emailVerified: true,
    })
  }

  return normalizeAssertion({
    provider: PHONE_OTP_PROVIDER_ID,
    providerUserId: verification.target,
    phone: verification.target,
    phoneVerified: true,
  })
}
