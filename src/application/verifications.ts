import type { AuthServiceRuntime } from './runtime.js'
import { optionalProp } from './optional.js'
import { audit } from './support.js'
import {
  AuditEventType,
  toVerificationResendWindow,
  VerificationStatus,
  type AuthIdentityProvider,
  type ConsumeVerificationInput,
  type CreateVerificationInput,
  type CreateVerificationResult,
  type GetVerificationResendWindowInput,
  type OtpChannel,
  type Verification,
  type VerificationResendWindow,
} from '../domain/types.js'
import { UniAuthError, UniAuthErrorCode, invalidInput } from '../errors.js'
import { generateSecret } from '../utils/secrets.js'
import { addSeconds, assertValidDate } from '../utils/time.js'

type CreateVerificationRecordInput = CreateVerificationInput & {
  readonly now: Date
  readonly provider?: AuthIdentityProvider
  readonly channel?: OtpChannel
}

export async function createVerification(
  runtime: AuthServiceRuntime,
  input: CreateVerificationInput,
): Promise<CreateVerificationResult> {
  return runtime.transaction.run(async () => {
    const now = input.now ?? runtime.clock.now()
    return createVerificationRecord(runtime, { ...input, now })
  })
}

export async function getVerification(
  runtime: AuthServiceRuntime,
  verificationId: Verification['id'],
): Promise<Verification> {
  const verification = await runtime.repos.verificationRepo.findById(verificationId)

  if (!verification) {
    throw new UniAuthError(UniAuthErrorCode.VerificationNotFound, 'Verification was not found.')
  }

  return verification
}

export async function getVerificationResendWindow(
  runtime: AuthServiceRuntime,
  input: GetVerificationResendWindowInput,
): Promise<VerificationResendWindow> {
  const verification = await getVerification(runtime, input.verificationId)
  const now = input.now ?? runtime.clock.now()
  const cooldownSeconds = resolveVerificationResendCooldownSeconds(runtime, input.cooldownSeconds)

  assertValidDate(now, 'Verification resend window time is invalid.')

  return toVerificationResendWindow(verification, {
    now,
    cooldownSeconds,
  })
}

export async function consumeVerification(
  runtime: AuthServiceRuntime,
  input: ConsumeVerificationInput,
): Promise<Verification> {
  return runtime.transaction.run(async () => {
    return consumeVerificationRecord(runtime, input)
  })
}

export async function createVerificationRecord(
  runtime: AuthServiceRuntime,
  input: CreateVerificationRecordInput,
): Promise<CreateVerificationResult> {
  const secret = input.secret ?? generateSecret()
  const trimmedTarget = input.target.trim()

  if (!trimmedTarget) {
    throw invalidInput('Verification target is required.')
  }

  const target = runtime.normalizer.normalizeTarget(trimmedTarget)

  if (!target) {
    throw invalidInput('Verification target is required.')
  }

  const expiresAt = resolveVerificationExpiresAt(runtime, input)

  const verification: Verification = {
    id: runtime.idGenerator.verificationId(),
    purpose: input.purpose,
    target,
    ...optionalProp('provider', input.provider),
    ...optionalProp('channel', input.channel),
    secretHash: await runtime.secretHasher.hash(secret),
    status: VerificationStatus.Pending,
    createdAt: input.now,
    expiresAt,
    ...optionalProp('metadata', input.metadata),
  }

  const created = await runtime.repos.verificationRepo.create(verification)
  await audit(runtime, AuditEventType.VerificationCreated, input.now, {
    metadata: { verificationId: created.id, purpose: created.purpose },
  })

  return { verification: created, secret }
}

export async function consumeVerificationRecord(
  runtime: AuthServiceRuntime,
  input: ConsumeVerificationInput,
): Promise<Verification> {
  const now = input.now ?? runtime.clock.now()
  const verification = await runtime.repos.verificationRepo.findById(input.verificationId)

  if (!verification) {
    throw new UniAuthError(UniAuthErrorCode.VerificationNotFound, 'Verification was not found.')
  }

  if (verification.status === VerificationStatus.Consumed) {
    throw new UniAuthError(
      UniAuthErrorCode.VerificationConsumed,
      'Verification has already been consumed.',
    )
  }

  if (verification.expiresAt.getTime() <= now.getTime()) {
    throw new UniAuthError(UniAuthErrorCode.VerificationExpired, 'Verification has expired.')
  }

  if (!(await runtime.secretHasher.verify(input.secret, verification.secretHash))) {
    throw new UniAuthError(
      UniAuthErrorCode.VerificationInvalidSecret,
      'Verification secret is invalid.',
    )
  }

  const consumed = await runtime.repos.verificationRepo.update(verification.id, {
    status: VerificationStatus.Consumed,
    consumedAt: now,
  })
  await audit(runtime, AuditEventType.VerificationConsumed, now, {
    metadata: { verificationId: consumed.id, purpose: consumed.purpose },
  })

  return consumed
}

function resolveVerificationExpiresAt(
  runtime: AuthServiceRuntime,
  input: CreateVerificationRecordInput,
): Date {
  assertValidDate(input.now, 'Verification creation time is invalid.')

  const ttlSeconds = input.ttlSeconds ?? runtime.verificationTtlSeconds

  if (!Number.isFinite(ttlSeconds) || ttlSeconds < 0) {
    throw invalidInput('Verification TTL must be a non-negative number of seconds.')
  }

  return addSeconds(input.now, ttlSeconds)
}

function resolveVerificationResendCooldownSeconds(
  runtime: AuthServiceRuntime,
  cooldownSeconds: number | undefined,
): number {
  const resolved = cooldownSeconds ?? runtime.verificationResendCooldownSeconds

  if (!Number.isInteger(resolved) || resolved < 0) {
    throw invalidInput('Verification resend cooldown must be a non-negative integer.')
  }

  return resolved
}
