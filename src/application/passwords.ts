import { optionalProp } from './optional.js'
import { AuthPolicyAction } from './policy.js'
import type { AuthServiceRuntime } from './runtime.js'
import { createSessionRecord } from './sessions.js'
import {
  audit,
  enforceRateLimit,
  ensureReAuth,
  getActiveUser,
  isActiveIdentity,
  rateLimitKey,
} from './support.js'
import { consumeVerificationRecord, createVerificationRecord } from './verifications.js'
import {
  AuditEventType,
  AuthIdentityStatus,
  CredentialType,
  OtpChannel,
  PASSWORD_PROVIDER_ID,
  VerificationPurpose,
  type AuthIdentity,
  type AuthResult,
  type ChangePasswordInput,
  type Credential,
  type FinishEmailPasswordRecoveryInput,
  type SetPasswordInput,
  type SignInWithPasswordInput,
  type StartEmailPasswordRecoveryInput,
  type StartEmailPasswordRecoveryResult,
  type User,
  type Verification,
} from '../domain/types.js'
import { UniAuthError, UniAuthErrorCode, invalidCredentials, invalidInput } from '../errors.js'
import { RateLimitAction, type PasswordHasher } from '../ports.js'
import { normalizeEmail } from '../utils/normalization.js'
import { generateSecret } from '../utils/secrets.js'

const DEFAULT_PASSWORD_RECOVERY_SUBJECT = 'Reset your password'
const PasswordAuditMode = {
  Password: 'password',
} as const

export async function signInWithPassword(
  runtime: AuthServiceRuntime,
  input: SignInWithPasswordInput,
): Promise<AuthResult> {
  const now = input.now ?? runtime.clock.now()
  const email = normalizePasswordEmail(input.email)
  assertPassword(input.password)
  const passwordHasher = getPasswordHasher(runtime)

  await enforceRateLimit(runtime, {
    action: RateLimitAction.PasswordSignIn,
    key: rateLimitKey(OtpChannel.Email, email),
    now,
    metadata: { provider: PASSWORD_PROVIDER_ID },
  })

  return runtime.transaction.run(async () => {
    const credential = await findPasswordCredentialByEmail(runtime, email)
    const identity = await findUsablePasswordIdentity(runtime, credential, email)

    if (!(await passwordHasher.verify(input.password, credential.passwordHash))) {
      throw invalidCredentials()
    }

    const user = await findUsableCredentialUser(runtime, credential)
    const session = await createSessionRecord(runtime, {
      userId: user.id,
      now,
      ...optionalProp('expiresAt', input.sessionExpiresAt),
      ...optionalProp('metadata', input.metadata),
    })
    await audit(runtime, AuditEventType.SignIn, now, {
      userId: user.id,
      identityId: identity.id,
      sessionId: session.id,
      metadata: { mode: PasswordAuditMode.Password },
    })

    return {
      user,
      identity,
      session,
      isNewUser: false,
      isNewIdentity: false,
    }
  })
}

export async function setPassword(
  runtime: AuthServiceRuntime,
  input: SetPasswordInput,
): Promise<Credential> {
  return runtime.transaction.run(async () => {
    const now = input.now ?? runtime.clock.now()
    const user = await getActiveUser(runtime, input.userId)
    await ensureReAuth(runtime, AuthPolicyAction.SetPassword, user.id, input.reAuthenticatedAt, now)

    const email = normalizePasswordEmail(input.email)
    assertPassword(input.password)
    const passwordHasher = getPasswordHasher(runtime)
    const existingForEmail = await runtime.repos.credentialRepo.findPasswordByEmail(email)

    if (existingForEmail && existingForEmail.userId !== user.id) {
      throw new UniAuthError(UniAuthErrorCode.CredentialAlreadyExists, 'Credential already exists.')
    }

    const existingForUser = await runtime.repos.credentialRepo.findPasswordByUserId(user.id)

    if (existingForUser && existingForUser.subject !== email) {
      throw invalidInput('Password credential email cannot be changed.')
    }

    const passwordHash = await passwordHasher.hash(input.password)
    await ensurePasswordIdentity(runtime, user, email, now)

    if (existingForUser) {
      return runtime.repos.credentialRepo.update(existingForUser.id, {
        passwordHash,
        updatedAt: now,
        ...optionalProp('metadata', input.metadata),
      })
    }

    return runtime.repos.credentialRepo.create({
      id: runtime.idGenerator.credentialId(),
      userId: user.id,
      type: CredentialType.Password,
      subject: email,
      passwordHash,
      createdAt: now,
      updatedAt: now,
      ...optionalProp('metadata', input.metadata),
    })
  })
}

export async function changePassword(
  runtime: AuthServiceRuntime,
  input: ChangePasswordInput,
): Promise<Credential> {
  return runtime.transaction.run(async () => {
    const now = input.now ?? runtime.clock.now()
    const user = await getActiveUser(runtime, input.userId)
    await ensureReAuth(
      runtime,
      AuthPolicyAction.ChangePassword,
      user.id,
      input.reAuthenticatedAt,
      now,
    )

    assertPassword(input.newPassword)
    const passwordHasher = getPasswordHasher(runtime)
    const credential = await runtime.repos.credentialRepo.findPasswordByUserId(user.id)

    if (
      !credential ||
      !(await passwordHasher.verify(input.currentPassword, credential.passwordHash))
    ) {
      throw invalidCredentials()
    }

    await findUsablePasswordIdentity(runtime, credential, credential.subject)

    return runtime.repos.credentialRepo.update(credential.id, {
      passwordHash: await passwordHasher.hash(input.newPassword),
      updatedAt: now,
      ...optionalProp('metadata', input.metadata),
    })
  })
}

export async function startEmailPasswordRecovery(
  runtime: AuthServiceRuntime,
  input: StartEmailPasswordRecoveryInput,
): Promise<StartEmailPasswordRecoveryResult> {
  const now = input.now ?? runtime.clock.now()
  const email = normalizePasswordEmail(input.email)

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
      ...optionalProp('metadata', input.metadata),
    })
  })
}

function normalizePasswordEmail(email: string): string {
  const normalized = normalizeEmail(email)

  if (!normalized) {
    throw invalidInput('Email is required.')
  }

  return normalized
}

function assertPassword(password: string): void {
  if (!password) {
    throw invalidInput('Password is required.')
  }
}

function getPasswordHasher(runtime: AuthServiceRuntime): PasswordHasher {
  if (!runtime.passwordHasher) {
    throw invalidInput('Password hasher is required for password flows.')
  }

  return runtime.passwordHasher
}

async function ensurePasswordIdentity(
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

async function findUsablePasswordIdentity(
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

async function findPasswordCredentialByEmail(
  runtime: AuthServiceRuntime,
  email: string,
): Promise<Credential> {
  const credential = await runtime.repos.credentialRepo.findPasswordByEmail(email)

  if (!credential) {
    throw invalidCredentials()
  }

  return credential
}

async function findUsableCredentialUser(
  runtime: AuthServiceRuntime,
  credential: Credential,
): Promise<User> {
  const user = await runtime.repos.userRepo.findById(credential.userId)

  if (!user || user.disabledAt) {
    throw invalidCredentials()
  }

  return user
}

async function findPasswordRecoveryVerification(
  runtime: AuthServiceRuntime,
  verificationId: Verification['id'],
): Promise<Verification> {
  const verification = await runtime.repos.verificationRepo.findById(verificationId)

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
