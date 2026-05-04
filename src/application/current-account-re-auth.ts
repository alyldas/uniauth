import { listActiveIdentitiesForUser } from './accounts/shared.js'
import { optionalProp } from './optional.js'
import { normalizeOtpTarget } from './otp-delivery.js'
import { startOtpChallenge } from './otp.js'
import {
  getPasswordHasher,
  findUsablePasswordIdentity,
  assertPassword,
} from './passwords/shared.js'
import type { AuthServiceRuntime } from './runtime.js'
import { resolveSessionContext } from './session-context.js'
import type {
  AuthIdentity,
  ConfirmCurrentAccountPasswordByTokenInput,
  CurrentAccountPasswordReAuthConfirmation,
  OtpChannel as OtpChannelType,
  StartCurrentAccountOtpReAuthInput,
  StartOtpChallengeResult,
} from '../domain/types.js'
import { OtpChannel, VerificationPurpose } from '../domain/types.js'
import { invalidCredentials, invalidInput } from '../errors.js'

const CURRENT_ACCOUNT_RE_AUTH_TARGET_ERROR =
  'Identity cannot be used for current-account OTP re-auth.'

export async function startCurrentAccountOtpReAuth(
  runtime: AuthServiceRuntime,
  input: StartCurrentAccountOtpReAuthInput,
): Promise<StartOtpChallengeResult> {
  const now = input.now ?? runtime.clock.now()
  const { user } = await resolveSessionContext(runtime, {
    sessionToken: input.sessionToken,
    now,
  })
  const identities = await listActiveIdentitiesForUser(runtime, user.id)
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
    now,
    ...(input.metadata ? { metadata: input.metadata } : {}),
  })
}

export async function confirmCurrentAccountPasswordByToken(
  runtime: AuthServiceRuntime,
  input: ConfirmCurrentAccountPasswordByTokenInput,
): Promise<CurrentAccountPasswordReAuthConfirmation> {
  return runtime.transaction.run(async () => {
    const now = input.now ?? runtime.clock.now()
    const { user } = await resolveSessionContext(runtime, {
      sessionToken: input.sessionToken,
      now,
    })

    assertPassword(input.currentPassword)

    const credential = await runtime.repos.credentialRepo.findPasswordByUserId(user.id)

    if (!credential) {
      throw invalidCredentials()
    }

    const passwordHasher = getPasswordHasher(runtime)

    if (!(await passwordHasher.verify(input.currentPassword, credential.passwordHash))) {
      throw invalidCredentials()
    }

    await findUsablePasswordIdentity(runtime, credential, credential.subject)

    return {
      userId: user.id,
      reAuthenticatedAt: now,
    }
  })
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
