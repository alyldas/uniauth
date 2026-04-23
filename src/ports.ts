import type {
  AuditEvent,
  AuthIdentity,
  AuthIdentityProvider,
  Credential,
  CredentialId,
  FinishInput,
  IdentityId,
  OtpChannel,
  ProviderIdentityAssertion,
  Session,
  SessionId,
  User,
  UserId,
  Verification,
  VerificationId,
  VerificationPurpose,
} from './domain/types.js'
import type { SecretHasher } from './utils/secrets.js'

export const RateLimitAction = {
  ProviderSignIn: 'provider:sign-in',
  OtpStart: 'otp:start',
  OtpFinish: 'otp:finish',
  MagicLinkStart: 'magic-link:start',
  MagicLinkFinish: 'magic-link:finish',
  PasswordSignIn: 'password:sign-in',
  PasswordRecoveryStart: 'password-recovery:start',
  PasswordRecoveryFinish: 'password-recovery:finish',
} as const

export type RateLimitAction = (typeof RateLimitAction)[keyof typeof RateLimitAction]

export interface RateLimitAttempt {
  readonly action: RateLimitAction
  readonly key: string
  readonly now: Date
  readonly metadata?: Record<string, unknown>
}

export interface RateLimitDecision {
  readonly allowed: boolean
  readonly retryAfterSeconds?: number
  readonly resetAt?: Date
}

export interface RateLimiter {
  consume(input: RateLimitAttempt): Promise<RateLimitDecision>
}

export interface OtpSecretGeneratorInput {
  readonly purpose: VerificationPurpose
  readonly channel: OtpChannel
  readonly target: string
  readonly now: Date
}

export type OtpSecretGenerator = (input: OtpSecretGeneratorInput) => string | Promise<string>

export interface PasswordHasher {
  hash(password: string): Promise<string>
  verify(password: string, passwordHash: string): Promise<boolean>
}

export interface AuthProvider {
  readonly id: AuthIdentityProvider
  finish(input: FinishInput): Promise<ProviderIdentityAssertion>
}

export interface UserRepo {
  findById(id: UserId): Promise<User | undefined>
  create(user: User): Promise<User>
  update(id: UserId, patch: Partial<Omit<User, 'id' | 'createdAt'>>): Promise<User>
}

export interface IdentityRepo {
  findById(id: IdentityId): Promise<AuthIdentity | undefined>
  findByProviderUserId(
    provider: AuthIdentityProvider,
    providerUserId: string,
  ): Promise<AuthIdentity | undefined>
  findByVerifiedEmail(email: string): Promise<readonly AuthIdentity[]>
  findByVerifiedPhone(phone: string): Promise<readonly AuthIdentity[]>
  listByUserId(userId: UserId): Promise<readonly AuthIdentity[]>
  create(identity: AuthIdentity): Promise<AuthIdentity>
  update(
    id: IdentityId,
    patch: Partial<Omit<AuthIdentity, 'id' | 'createdAt'>>,
  ): Promise<AuthIdentity>
}

export interface CredentialRepo {
  findPasswordByEmail(email: string): Promise<Credential | undefined>
  findPasswordByUserId(userId: UserId): Promise<Credential | undefined>
  listByUserId(userId: UserId): Promise<readonly Credential[]>
  create(credential: Credential): Promise<Credential>
  update(
    id: CredentialId,
    patch: Partial<Omit<Credential, 'id' | 'type' | 'createdAt'>>,
  ): Promise<Credential>
}

export interface VerificationRepo {
  findById(id: VerificationId): Promise<Verification | undefined>
  create(verification: Verification): Promise<Verification>
  update(
    id: VerificationId,
    patch: Partial<Omit<Verification, 'id' | 'createdAt'>>,
  ): Promise<Verification>
}

export interface SessionRepo {
  findById(id: SessionId): Promise<Session | undefined>
  listByUserId(userId: UserId): Promise<readonly Session[]>
  create(session: Session): Promise<Session>
  update(id: SessionId, patch: Partial<Omit<Session, 'id' | 'createdAt'>>): Promise<Session>
}

export interface AuditLogRepo {
  append(event: AuditEvent): Promise<void>
}

export interface EmailSender {
  sendEmail(input: {
    readonly to: string
    readonly subject: string
    readonly text: string
    readonly metadata?: Record<string, unknown>
  }): Promise<void>
}

export interface SmsSender {
  sendSms(input: {
    readonly to: string
    readonly text: string
    readonly metadata?: Record<string, unknown>
  }): Promise<void>
}

export interface AuthServiceInfrastructure {
  readonly emailSender?: EmailSender
  readonly smsSender?: SmsSender
  readonly secretHasher?: SecretHasher
  readonly rateLimiter?: RateLimiter
  readonly otpSecretLength?: number
  readonly otpSecretGenerator?: OtpSecretGenerator
  readonly emailOtpSubject?: string
  readonly passwordHasher?: PasswordHasher
}

export interface ProviderRegistry {
  get(provider: AuthIdentityProvider): Promise<AuthProvider | undefined>
}

export interface UnitOfWork {
  run<T>(operation: () => Promise<T>): Promise<T>
}

export interface AuthServiceRepositories {
  readonly userRepo: UserRepo
  readonly identityRepo: IdentityRepo
  readonly credentialRepo: CredentialRepo
  readonly verificationRepo: VerificationRepo
  readonly sessionRepo: SessionRepo
  readonly auditLogRepo: AuditLogRepo
}
