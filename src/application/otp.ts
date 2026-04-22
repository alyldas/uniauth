import type { AuthServiceRuntime } from './runtime.js'
import { getOtpDelivery, normalizeOtpTarget, type SupportedOtpChannel } from './otp-delivery.js'
import { optionalProp } from './optional.js'
import { normalizeAssertion, signInWithAssertion } from './sign-in.js'
import { createVerificationRecord, consumeVerificationRecord } from './verifications.js'
import type {
  AuthResult,
  FinishEmailOtpSignInInput,
  FinishOtpChallengeInput,
  FinishOtpSignInInput,
  OtpChannel as OtpChannelType,
  ProviderIdentityAssertion,
  StartEmailOtpSignInInput,
  StartEmailOtpSignInResult,
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
import { generateOtpSecret } from '../utils/secrets.js'

export async function startOtpChallenge(
  runtime: AuthServiceRuntime,
  input: StartOtpChallengeInput,
): Promise<StartOtpChallengeResult> {
  const now = input.now ?? runtime.clock.now()
  const target = normalizeOtpTarget(input.channel, input.target)
  const delivery = getOtpDelivery(runtime, input.channel)
  const created = await runtime.transaction.run(async () => {
    return createVerificationRecord(runtime, {
      purpose: input.purpose,
      target,
      secret: input.secret ?? generateOtpSecret(),
      ...optionalProp('ttlSeconds', input.ttlSeconds),
      now,
      metadata: {
        ...input.metadata,
        channel: input.channel,
        provider: delivery.provider,
      },
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
  return runtime.transaction.run(async () => {
    const now = input.now ?? runtime.clock.now()
    const consumed = await consumeOtpChallengeRecord(runtime, {
      verificationId: input.verificationId,
      secret: input.secret,
      ...optionalProp('purpose', input.purpose),
      ...optionalProp('channel', input.channel),
      now,
      context: 'OTP challenge',
    })

    return consumed.verification
  })
}

export async function finishOtpSignIn(
  runtime: AuthServiceRuntime,
  input: FinishOtpSignInInput,
): Promise<AuthResult> {
  return runtime.transaction.run(async () => {
    const now = input.now ?? runtime.clock.now()
    const consumed = await consumeOtpChallengeRecord(runtime, {
      verificationId: input.verificationId,
      secret: input.secret,
      purpose: VerificationPurpose.SignIn,
      ...optionalProp('channel', input.channel),
      now,
      context: 'OTP sign-in',
    })

    return signInWithAssertion(
      runtime,
      assertionFromOtpVerification(consumed.verification, consumed.channel),
      {
        now,
        ...optionalProp('sessionExpiresAt', input.sessionExpiresAt),
        ...optionalProp('metadata', input.metadata),
      },
    )
  })
}

export async function startEmailOtpSignIn(
  runtime: AuthServiceRuntime,
  input: StartEmailOtpSignInInput,
): Promise<StartEmailOtpSignInResult> {
  const started = await startOtpChallenge(runtime, {
    purpose: VerificationPurpose.SignIn,
    channel: OtpChannel.Email,
    target: input.email,
    ...optionalProp('secret', input.secret),
    ...optionalProp('ttlSeconds', input.ttlSeconds),
    ...optionalProp('now', input.now),
    ...optionalProp('metadata', input.metadata),
  })

  return {
    verificationId: started.verificationId,
    expiresAt: started.expiresAt,
    delivery: OtpChannel.Email,
  }
}

export async function finishEmailOtpSignIn(
  runtime: AuthServiceRuntime,
  input: FinishEmailOtpSignInInput,
): Promise<AuthResult> {
  return finishOtpSignIn(runtime, {
    verificationId: input.verificationId,
    secret: input.secret,
    channel: OtpChannel.Email,
    ...optionalProp('now', input.now),
    ...optionalProp('sessionExpiresAt', input.sessionExpiresAt),
    ...optionalProp('metadata', input.metadata),
  })
}

async function consumeOtpChallengeRecord(
  runtime: AuthServiceRuntime,
  input: {
    readonly verificationId: Verification['id']
    readonly secret: string
    readonly purpose?: VerificationPurpose
    readonly channel?: OtpChannelType
    readonly now: Date
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

  const consumed = await consumeVerificationRecord(runtime, {
    verificationId: input.verificationId,
    secret: input.secret,
    now: input.now,
  })

  return { verification: consumed, channel }
}

function otpChannelFromVerification(verification: Verification): SupportedOtpChannel | undefined {
  const channel = verification.metadata?.channel

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
