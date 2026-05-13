import type { AuthServiceRuntime } from './runtime.js'
import { normalizeMetadataRecord } from './metadata.js'
import { optionalProp } from './optional.js'
import { audit } from './support.js'
import {
  AuditEventType,
  isConsumedVerification,
  isExpiredVerification,
  isUsableVerification,
  toVerificationResendWindow,
  VerificationStatus,
  type AuthIdentityProvider,
  type ConsumeVerificationInput,
  type CancelVerificationInput,
  type CreateVerificationInput,
  type CreateVerificationResult,
  type GetVerificationResendWindowInput,
  type OtpChannel,
  type Verification,
  type VerificationResendWindow,
} from '../domain/types.js'
import { UniAuthError, UniAuthErrorCode, invalidInput, rateLimited } from '../errors.js'
import type { RateLimitAction } from '../contracts.js'
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

export async function cancelVerification(
  runtime: AuthServiceRuntime,
  input: CancelVerificationInput,
): Promise<Verification> {
  return runtime.transaction.run(async () => {
    const now = input.now ?? runtime.clock.now()
    const verification = await getVerificationForUpdate(runtime, input.verificationId)

    return cancelVerificationRecord(runtime, verification, now, input.metadata)
  })
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

export async function getVerificationForUpdate(
  runtime: AuthServiceRuntime,
  verificationId: Verification['id'],
): Promise<Verification> {
  const verification = await runtime.repos.verificationRepo.findByIdForUpdate(verificationId)

  if (!verification) {
    throw new UniAuthError(UniAuthErrorCode.VerificationNotFound, 'Verification was not found.')
  }

  return verification
}

export async function requireVerificationResendAllowed(
  runtime: AuthServiceRuntime,
  verification: Verification,
  input: {
    readonly action: RateLimitAction
    readonly now: Date
  },
): Promise<VerificationResendWindow> {
  assertValidDate(input.now, 'Verification resend time is invalid.')

  const window = toVerificationResendWindow(verification, {
    now: input.now,
    cooldownSeconds: resolveVerificationResendCooldownSeconds(runtime, undefined),
  })

  if (isConsumedVerification(verification)) {
    throw new UniAuthError(
      UniAuthErrorCode.VerificationConsumed,
      'Verification has already been consumed.',
    )
  }

  if (window.expired) {
    throw new UniAuthError(UniAuthErrorCode.VerificationExpired, 'Verification has expired.')
  }

  if (window.resendAllowed) {
    return window
  }

  const details = {
    action: input.action,
    retryAfterSeconds: window.cooldownRemainingSeconds,
    resetAt: window.resendAvailableAt.toISOString(),
  }

  await audit(runtime, AuditEventType.RateLimited, input.now, {
    metadata: details,
  })

  throw rateLimited(details)
}

export async function createVerificationRecord(
  runtime: AuthServiceRuntime,
  input: CreateVerificationRecordInput,
): Promise<CreateVerificationResult> {
  const secret = resolveVerificationSecret(input.secret)
  const metadata = normalizeVerificationMetadata(input.metadata)
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
    ...optionalProp('metadata', metadata),
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
  const secret = requireVerificationSecret(input.secret)
  const verification = await runtime.repos.verificationRepo.findByIdForUpdate(input.verificationId)

  if (!verification) {
    throw new UniAuthError(UniAuthErrorCode.VerificationNotFound, 'Verification was not found.')
  }

  if (isConsumedVerification(verification)) {
    throw new UniAuthError(
      UniAuthErrorCode.VerificationConsumed,
      'Verification has already been consumed.',
    )
  }

  if (isExpiredVerification(verification, now)) {
    throw new UniAuthError(UniAuthErrorCode.VerificationExpired, 'Verification has expired.')
  }

  if (!(await runtime.secretHasher.verify(secret, verification.secretHash))) {
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

function resolveVerificationSecret(secret: string | undefined): string {
  if (secret === undefined) {
    return generateSecret()
  }

  return requireVerificationSecret(secret)
}

function requireVerificationSecret(secret: string): string {
  if (typeof secret !== 'string' || !secret.trim()) {
    throw invalidInput('Verification secret is required.')
  }

  return secret
}

export async function expireVerificationForResend(
  runtime: AuthServiceRuntime,
  verificationId: Verification['id'],
  now: Date,
): Promise<Verification> {
  assertValidDate(now, 'Verification resend time is invalid.')

  return runtime.repos.verificationRepo.update(verificationId, {
    expiresAt: now,
  })
}

export async function cancelVerificationRecord(
  runtime: AuthServiceRuntime,
  verification: Verification,
  now: Date,
  metadata?: Record<string, unknown>,
): Promise<Verification> {
  assertValidDate(now, 'Verification cancellation time is invalid.')
  const cancellationMetadata = normalizeVerificationMetadata(metadata)

  if (!isUsableVerification(verification, now)) {
    return verification
  }

  const cancelled = await runtime.repos.verificationRepo.update(verification.id, {
    expiresAt: now,
  })

  await audit(runtime, AuditEventType.VerificationCancelled, now, {
    metadata: {
      verificationId: cancelled.id,
      purpose: cancelled.purpose,
      ...(cancellationMetadata ?? {}),
    },
  })

  return cancelled
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

  const expiresAt = addSeconds(input.now, ttlSeconds)
  assertValidDate(expiresAt, 'Verification expiration time is invalid.')

  return expiresAt
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

export function mergeVerificationMetadata(
  current: Record<string, unknown> | undefined,
  next: Record<string, unknown> | undefined,
): Record<string, unknown> | undefined {
  const currentMetadata = normalizeVerificationMetadata(current)
  const nextMetadata = normalizeVerificationMetadata(next)

  if (!currentMetadata && !nextMetadata) {
    return undefined
  }

  return {
    ...(currentMetadata ?? {}),
    ...(nextMetadata ?? {}),
  }
}

function normalizeVerificationMetadata(
  metadata: Record<string, unknown> | undefined,
): Record<string, unknown> | undefined {
  return normalizeMetadataRecord(metadata, 'Verification metadata')
}
