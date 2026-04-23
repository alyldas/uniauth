import { optionalProp } from './optional.js'
import type { AuthServiceRuntime } from './runtime.js'
import { normalizeAssertion, signInWithAssertion } from './sign-in.js'
import { enforceRateLimit, rateLimitKey } from './support.js'
import { consumeVerificationRecord, createVerificationRecord } from './verifications.js'
import {
  EMAIL_MAGIC_LINK_PROVIDER_ID,
  OtpChannel,
  VerificationPurpose,
  type AuthResult,
  type FinishEmailMagicLinkSignInInput,
  type StartEmailMagicLinkSignInInput,
  type StartEmailMagicLinkSignInResult,
  type Verification,
} from '../domain/types.js'
import { UniAuthError, UniAuthErrorCode, invalidInput } from '../errors.js'
import { RateLimitAction } from '../ports.js'
import { normalizeEmail } from '../utils/normalization.js'
import { generateSecret } from '../utils/secrets.js'

const DEFAULT_EMAIL_MAGIC_LINK_SUBJECT = 'Your sign-in link'

export async function startEmailMagicLinkSignIn(
  runtime: AuthServiceRuntime,
  input: StartEmailMagicLinkSignInInput,
): Promise<StartEmailMagicLinkSignInResult> {
  const now = input.now ?? runtime.clock.now()
  const email = normalizeEmail(input.email)

  if (!email) {
    throw invalidInput('Email is required.')
  }

  if (!runtime.emailSender) {
    throw invalidInput('Email sender is required for email magic links.')
  }

  await enforceRateLimit(runtime, {
    action: RateLimitAction.MagicLinkStart,
    key: rateLimitKey(OtpChannel.Email, email),
    now,
    metadata: { delivery: OtpChannel.Email, purpose: VerificationPurpose.SignIn },
  })

  const created = await runtime.transaction.run(async () => {
    return createVerificationRecord(runtime, {
      purpose: VerificationPurpose.SignIn,
      target: email,
      provider: EMAIL_MAGIC_LINK_PROVIDER_ID,
      channel: OtpChannel.Email,
      secret: input.secret ?? generateSecret(),
      ...optionalProp('ttlSeconds', input.ttlSeconds),
      now,
      ...optionalProp('metadata', input.metadata),
    })
  })
  const link = await input.createLink({
    verificationId: created.verification.id,
    secret: created.secret,
    email,
    expiresAt: created.verification.expiresAt,
  })

  await runtime.emailSender.sendEmail({
    to: email,
    subject: DEFAULT_EMAIL_MAGIC_LINK_SUBJECT,
    text: `Sign in using this link: ${link}`,
    metadata: {
      verificationId: created.verification.id,
      purpose: created.verification.purpose,
      delivery: OtpChannel.Email,
      provider: EMAIL_MAGIC_LINK_PROVIDER_ID,
    },
  })

  return {
    verificationId: created.verification.id,
    expiresAt: created.verification.expiresAt,
    delivery: OtpChannel.Email,
  }
}

export async function finishEmailMagicLinkSignIn(
  runtime: AuthServiceRuntime,
  input: FinishEmailMagicLinkSignInInput,
): Promise<AuthResult> {
  const now = input.now ?? runtime.clock.now()
  const verification = await findEmailMagicLinkVerification(runtime, input.verificationId)

  await enforceRateLimit(runtime, {
    action: RateLimitAction.MagicLinkFinish,
    key: rateLimitKey(OtpChannel.Email, verification.id),
    now,
    metadata: { delivery: OtpChannel.Email, purpose: verification.purpose },
  })

  return runtime.transaction.run(async () => {
    await findEmailMagicLinkVerification(runtime, input.verificationId)
    const consumed = await consumeVerificationRecord(runtime, {
      verificationId: input.verificationId,
      secret: input.secret,
      now,
    })

    return signInWithAssertion(
      runtime,
      normalizeAssertion({
        provider: EMAIL_MAGIC_LINK_PROVIDER_ID,
        providerUserId: consumed.target,
        email: consumed.target,
        emailVerified: true,
      }),
      {
        now,
        ...optionalProp('sessionExpiresAt', input.sessionExpiresAt),
        ...optionalProp('metadata', input.metadata),
      },
    )
  })
}

async function findEmailMagicLinkVerification(
  runtime: AuthServiceRuntime,
  verificationId: Verification['id'],
): Promise<Verification> {
  const verification = await runtime.repos.verificationRepo.findById(verificationId)

  if (!verification) {
    throw new UniAuthError(UniAuthErrorCode.VerificationNotFound, 'Verification was not found.')
  }

  if (!isEmailMagicLinkVerification(verification)) {
    throw invalidInput('Verification cannot be used for email magic link sign-in.')
  }

  return verification
}

function isEmailMagicLinkVerification(verification: Verification): boolean {
  return (
    verification.purpose === VerificationPurpose.SignIn &&
    verification.provider === EMAIL_MAGIC_LINK_PROVIDER_ID
  )
}
