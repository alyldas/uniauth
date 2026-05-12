import { audit } from '../support.js'
import type { AuthServiceRuntime } from '../runtime.js'
import {
  AuditEventType,
  AuthIdentityStatus,
  PASSWORD_PROVIDER_ID,
  VerificationPurpose,
  isActiveIdentity,
  isActiveUser,
  type AuthIdentity,
  type Credential,
  type User,
  type Verification,
} from '../../domain/types.js'
import { UniAuthError, UniAuthErrorCode, invalidCredentials, invalidInput } from '../../errors.js'
import type { PasswordHasher } from '../../contracts.js'

export const DEFAULT_PASSWORD_RECOVERY_SUBJECT = 'Reset your password'
export const PasswordAuditMode = {
  Password: 'password',
} as const

export function normalizePasswordEmail(
  runtime: Pick<AuthServiceRuntime, 'normalizer'>,
  email: string,
): string {
  const trimmed = email.trim()

  if (!trimmed) {
    throw invalidInput('Email is required.')
  }

  const normalized = runtime.normalizer.normalizeEmail(trimmed)

  if (!normalized) {
    throw invalidInput('Email is required.')
  }

  return normalized
}

export function assertPassword(password: string): void {
  if (!password) {
    throw invalidInput('Password is required.')
  }
}

export function getPasswordHasher(runtime: AuthServiceRuntime): PasswordHasher {
  if (!runtime.passwordHasher) {
    throw invalidInput('Password hasher is required for password flows.')
  }

  return runtime.passwordHasher
}

export async function ensurePasswordIdentity(
  runtime: AuthServiceRuntime,
  user: User,
  email: string,
  now: Date,
): Promise<AuthIdentity> {
  const existing = await runtime.repos.identityRepo.findByProviderUserId(
    PASSWORD_PROVIDER_ID,
    email,
  )

  if (existing) {
    if (existing.userId !== user.id || !isActiveIdentity(existing)) {
      throw new UniAuthError(UniAuthErrorCode.IdentityAlreadyLinked, 'Identity cannot be linked.')
    }

    return existing
  }

  const identity = await runtime.repos.identityRepo.create({
    id: runtime.idGenerator.identityId(),
    userId: user.id,
    provider: PASSWORD_PROVIDER_ID,
    providerUserId: email,
    status: AuthIdentityStatus.Active,
    email,
    emailVerified: true,
    createdAt: now,
    updatedAt: now,
  })
  await audit(runtime, AuditEventType.IdentityLinked, now, {
    userId: user.id,
    identityId: identity.id,
    metadata: { mode: PasswordAuditMode.Password },
  })

  return identity
}

export async function findUsablePasswordIdentity(
  runtime: AuthServiceRuntime,
  credential: Credential,
  email: string,
): Promise<AuthIdentity> {
  const identity = await runtime.repos.identityRepo.findByProviderUserId(
    PASSWORD_PROVIDER_ID,
    email,
  )

  if (!identity || identity.userId !== credential.userId || !isActiveIdentity(identity)) {
    throw invalidCredentials()
  }

  return identity
}

export async function findPasswordCredentialByEmail(
  runtime: AuthServiceRuntime,
  email: string,
): Promise<Credential> {
  const credential = await runtime.repos.credentialRepo.findPasswordByEmail(email)

  if (!credential) {
    throw invalidCredentials()
  }

  return credential
}

export async function findUsableCredentialUser(
  runtime: AuthServiceRuntime,
  credential: Credential,
): Promise<User> {
  const user = await runtime.repos.userRepo.findById(credential.userId)

  if (!user || !isActiveUser(user)) {
    throw invalidCredentials()
  }

  return user
}

export async function findPasswordRecoveryVerification(
  runtime: AuthServiceRuntime,
  verificationId: Verification['id'],
  options: { readonly lock?: boolean } = {},
): Promise<Verification> {
  const verification = await (options.lock
    ? runtime.repos.verificationRepo.findByIdForUpdate(verificationId)
    : runtime.repos.verificationRepo.findById(verificationId))

  if (!verification) {
    throw new UniAuthError(UniAuthErrorCode.VerificationNotFound, 'Verification was not found.')
  }

  if (!isPasswordRecoveryVerification(verification)) {
    throw invalidInput('Verification cannot be used for password recovery.')
  }

  return verification
}

function isPasswordRecoveryVerification(verification: Verification): boolean {
  return (
    verification.purpose === VerificationPurpose.Recovery &&
    verification.provider === PASSWORD_PROVIDER_ID
  )
}
