import type { AuthServiceRuntime } from './runtime.js'
import { optionalProp } from './optional.js'
import { audit } from './support.js'
import {
  AuditEventType,
  VerificationStatus,
  type AuthIdentityProvider,
  type ConsumeVerificationInput,
  type CreateVerificationInput,
  type CreateVerificationResult,
  type OtpChannel,
  type Verification,
} from '../domain/types.js'
import { UniAuthError, UniAuthErrorCode, invalidInput } from '../errors.js'
import { normalizeTarget } from '../utils/normalization.js'
import { generateSecret } from '../utils/secrets.js'
import { addSeconds } from '../utils/time.js'

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
  const target = normalizeTarget(input.target)

  if (!target) {
    throw invalidInput('Verification target is required.')
  }

  const verification: Verification = {
    id: runtime.idGenerator.verificationId(),
    purpose: input.purpose,
    target,
    ...optionalProp('provider', input.provider),
    ...optionalProp('channel', input.channel),
    secretHash: await runtime.secretHasher.hash(secret),
    status: VerificationStatus.Pending,
    createdAt: input.now,
    expiresAt: addSeconds(input.now, input.ttlSeconds ?? runtime.verificationTtlSeconds),
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
