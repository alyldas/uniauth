import type {
  AuditEvent,
  AuthIdentity,
  AuthIdentityProvider,
  FinishInput,
  IdentityId,
  ProviderIdentityAssertion,
  Session,
  SessionId,
  User,
  UserId,
  Verification,
  VerificationId,
} from './domain/types.js'
import type { SecretHasher } from './utils/secrets.js'

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
  readonly verificationRepo: VerificationRepo
  readonly sessionRepo: SessionRepo
  readonly auditLogRepo: AuditLogRepo
}
