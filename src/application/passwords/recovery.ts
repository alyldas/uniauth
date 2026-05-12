import { optionalProp } from '../optional.js'
import { normalizeMetadataRecord } from '../metadata.js'
import type { AuthServiceRuntime } from '../runtime.js'
import { enforceRateLimit } from '../support.js'
import {
  cancelVerificationRecord,
  consumeVerificationRecord,
  createVerificationRecord,
  expireVerificationForResend,
  mergeVerificationMetadata,
  requireVerificationResendAllowed,
} from '../verifications.js'
import {
  type CancelEmailPasswordRecoveryInput,
  OtpChannel,
  PASSWORD_PROVIDER_ID,
  VerificationPurpose,
  type Credential,
  type FinishEmailPasswordRecoveryInput,
  type ResendEmailPasswordRecoveryInput,
  type StartEmailPasswordRecoveryInput,
  type StartEmailPasswordRecoveryResult,
  type Verification,
} from '../../domain/types.js'
import { invalidInput } from '../../errors.js'
import { RateLimitAction, rateLimitKey } from '../../ports.js'
import { generateSecret } from '../../utils/secrets.js'
import {
  DEFAULT_PASSWORD_RECOVERY_SUBJECT,
  assertPassword,
  findPasswordCredentialByEmail,
  findPasswordRecoveryVerification,
  findUsableCredentialUser,
  findUsablePasswordIdentity,
  getPasswordHasher,
  normalizePasswordEmail,
} from './shared.js'

export async function startEmailPasswordRecovery(
  runtime: AuthServiceRuntime,
  input: StartEmailPasswordRecoveryInput,
): Promise<StartEmailPasswordRecoveryResult> {
  const now = input.now ?? runtime.clock.now()
  const email = normalizePasswordEmail(runtime, input.email)

  if (!runtime.emailSender) {
    throw invalidInput('Email sender is required for password recovery.')
  }

  await enforceRateLimit(runtime, {
    action: RateLimitAction.PasswordRecoveryStart,
    key: rateLimitKey(OtpChannel.Email, email),
    now,
    metadata: { delivery: OtpChannel.Email, purpose: VerificationPurpose.Recovery },
  })

  const created = await runtime.transaction.run(async () => {
    return createVerificationRecord(runtime, {
      purpose: VerificationPurpose.Recovery,
      target: email,
      provider: PASSWORD_PROVIDER_ID,
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
    subject: DEFAULT_PASSWORD_RECOVERY_SUBJECT,
    text: `Reset your password using this link: ${link}`,
    metadata: {
      verificationId: created.verification.id,
      purpose: created.verification.purpose,
      delivery: OtpChannel.Email,
      provider: PASSWORD_PROVIDER_ID,
    },
  })

  return {
    verificationId: created.verification.id,
    expiresAt: created.verification.expiresAt,
    delivery: OtpChannel.Email,
  }
}

export async function finishEmailPasswordRecovery(
  runtime: AuthServiceRuntime,
  input: FinishEmailPasswordRecoveryInput,
): Promise<Credential> {
  const now = input.now ?? runtime.clock.now()
  const metadata = normalizePasswordRecoveryMetadata(input.metadata)
  assertPassword(input.newPassword)
  const passwordHasher = getPasswordHasher(runtime)
  const verification = await findPasswordRecoveryVerification(runtime, input.verificationId)

  await enforceRateLimit(runtime, {
    action: RateLimitAction.PasswordRecoveryFinish,
    key: rateLimitKey(OtpChannel.Email, verification.id),
    now,
    metadata: { delivery: OtpChannel.Email, purpose: verification.purpose },
  })

  return runtime.transaction.run(async () => {
    await findPasswordRecoveryVerification(runtime, input.verificationId)
    const consumed = await consumeVerificationRecord(runtime, {
      verificationId: input.verificationId,
      secret: input.secret,
      now,
    })
    const credential = await findPasswordCredentialByEmail(runtime, consumed.target)

    await findUsablePasswordIdentity(runtime, credential, consumed.target)
    await findUsableCredentialUser(runtime, credential)

    return runtime.repos.credentialRepo.update(credential.id, {
      passwordHash: await passwordHasher.hash(input.newPassword),
      updatedAt: now,
      ...optionalProp('metadata', metadata),
    })
  })
}

export async function resendEmailPasswordRecovery(
  runtime: AuthServiceRuntime,
  input: ResendEmailPasswordRecoveryInput,
): Promise<StartEmailPasswordRecoveryResult> {
  const now = input.now ?? runtime.clock.now()

  if (!runtime.emailSender) {
    throw invalidInput('Email sender is required for password recovery.')
  }
  const emailSender = runtime.emailSender

  const { created, verification } = await runtime.transaction.run(async () => {
    const verification = await findPasswordRecoveryVerification(runtime, input.verificationId, {
      lock: true,
    })

    await requireVerificationResendAllowed(runtime, verification, {
      action: RateLimitAction.PasswordRecoveryResend,
      now,
    })
    await enforceRateLimit(runtime, {
      action: RateLimitAction.PasswordRecoveryResend,
      key: rateLimitKey(OtpChannel.Email, verification.target),
      now,
      metadata: { delivery: OtpChannel.Email, purpose: verification.purpose },
    })

    const created = await createVerificationRecord(runtime, {
      purpose: verification.purpose,
      target: verification.target,
      provider: PASSWORD_PROVIDER_ID,
      channel: OtpChannel.Email,
      secret: input.secret ?? generateSecret(),
      ...optionalProp('ttlSeconds', input.ttlSeconds),
      now,
      ...optionalProp('metadata', mergeVerificationMetadata(verification.metadata, input.metadata)),
    })
    await expireVerificationForResend(runtime, verification.id, now)

    return {
      created,
      verification,
    }
  })
  const link = await input.createLink({
    verificationId: created.verification.id,
    secret: created.secret,
    email: verification.target,
    expiresAt: created.verification.expiresAt,
  })

  await emailSender.sendEmail({
    to: verification.target,
    subject: DEFAULT_PASSWORD_RECOVERY_SUBJECT,
    text: `Reset your password using this link: ${link}`,
    metadata: {
      verificationId: created.verification.id,
      purpose: created.verification.purpose,
      delivery: OtpChannel.Email,
      provider: PASSWORD_PROVIDER_ID,
    },
  })

  return {
    verificationId: created.verification.id,
    expiresAt: created.verification.expiresAt,
    delivery: OtpChannel.Email,
  }
}

export async function cancelEmailPasswordRecovery(
  runtime: AuthServiceRuntime,
  input: CancelEmailPasswordRecoveryInput,
): Promise<Verification> {
  return runtime.transaction.run(async () => {
    const now = input.now ?? runtime.clock.now()
    const verification = await findPasswordRecoveryVerification(runtime, input.verificationId, {
      lock: true,
    })

    return cancelVerificationRecord(runtime, verification, now, input.metadata)
  })
}

function normalizePasswordRecoveryMetadata(
  metadata: Record<string, unknown> | undefined,
): Record<string, unknown> | undefined {
  return normalizeMetadataRecord(metadata, 'Password recovery metadata')
}
