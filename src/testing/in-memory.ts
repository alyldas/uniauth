import {
  createAuthService,
  type DefaultAuthService,
  type DefaultAuthServiceOptions,
} from '../application/auth-service.js'
import { optionalProp } from '../application/optional.js'
import type { AuthPolicy } from '../application/policy.js'
import {
  AuthIdentityStatus,
  CredentialType,
  type AuditEvent,
  type AuthIdentity,
  type AuthIdentityProvider,
  type Clock,
  type Credential,
  type IdGenerator,
  type Session,
  type User,
  type Verification,
} from '../domain/types.js'
import { UniAuthError, UniAuthErrorCode } from '../errors.js'
import type {
  AuditLogRepo,
  AuthServiceRepositories,
  CredentialRepo,
  EmailSender,
  IdentityRepo,
  OtpSecretGenerator,
  PasswordHasher,
  RateLimitAttempt,
  RateLimitDecision,
  RateLimiter,
  SessionRepo,
  SmsSender,
  UnitOfWork,
  UserRepo,
  VerificationRepo,
} from '../ports.js'
import { createSequentialIdGenerator } from '../utils/ids.js'
import { normalizeEmail, normalizePhone } from '../utils/normalization.js'
import { hashSecret } from '../utils/secrets.js'
import type { SecretHasher } from '../utils/secrets.js'
import { InMemoryProviderRegistry } from './providers.js'

export class InMemoryAuthStore implements AuthServiceRepositories, UnitOfWork {
  private readonly users = new Map<User['id'], User>()
  private readonly identities = new Map<AuthIdentity['id'], AuthIdentity>()
  private readonly identityKeys = new Map<string, AuthIdentity['id']>()
  private readonly credentials = new Map<Credential['id'], Credential>()
  private readonly credentialKeys = new Map<string, Credential['id']>()
  private readonly credentialUserKeys = new Map<string, Credential['id']>()
  private readonly verifications = new Map<Verification['id'], Verification>()
  private readonly sessions = new Map<Session['id'], Session>()
  private readonly auditEvents: AuditEvent[] = []
  private transactionDepth = 0

  readonly userRepo: UserRepo = {
    findById: async (id) => this.users.get(id),
    create: async (user) => {
      this.users.set(user.id, user)
      return user
    },
    update: async (id, patch) => {
      const existing = this.users.get(id)

      if (!existing) {
        throw new UniAuthError(UniAuthErrorCode.UserNotFound, 'User was not found.')
      }

      const updated: User = { ...existing, ...patch }
      this.users.set(updated.id, updated)
      return updated
    },
  }

  readonly identityRepo: IdentityRepo = {
    findById: async (id) => this.identities.get(id),
    findByProviderUserId: async (provider, providerUserId) => {
      const id = this.identityKeys.get(this.identityKey(provider, providerUserId))
      return id ? this.identities.get(id) : undefined
    },
    findByVerifiedEmail: async (email) => {
      const normalizedEmail = normalizeEmail(email)
      return [...this.identities.values()].filter(
        (identity) =>
          identity.status === AuthIdentityStatus.Active &&
          identity.emailVerified === true &&
          identity.email === normalizedEmail,
      )
    },
    findByVerifiedPhone: async (phone) => {
      const normalizedPhone = normalizePhone(phone)
      return [...this.identities.values()].filter(
        (identity) =>
          identity.status === AuthIdentityStatus.Active &&
          identity.phoneVerified === true &&
          identity.phone === normalizedPhone,
      )
    },
    listByUserId: async (userId) =>
      [...this.identities.values()].filter((identity) => identity.userId === userId),
    create: async (identity) => {
      const key = this.identityKey(identity.provider, identity.providerUserId)

      if (this.identityKeys.has(key)) {
        throw new UniAuthError(UniAuthErrorCode.IdentityAlreadyLinked, 'Identity cannot be linked.')
      }

      this.identities.set(identity.id, identity)
      this.identityKeys.set(key, identity.id)
      return identity
    },
    update: async (id, patch) => {
      const existing = this.identities.get(id)

      if (!existing) {
        throw new UniAuthError(UniAuthErrorCode.IdentityNotFound, 'Identity was not found.')
      }

      const updated: AuthIdentity = { ...existing, ...patch }
      const oldKey = this.identityKey(existing.provider, existing.providerUserId)
      const newKey = this.identityKey(updated.provider, updated.providerUserId)
      const existingIdentityId = this.identityKeys.get(newKey)

      if (newKey !== oldKey && existingIdentityId) {
        throw new UniAuthError(UniAuthErrorCode.IdentityAlreadyLinked, 'Identity cannot be linked.')
      }

      this.identityKeys.delete(oldKey)
      this.identityKeys.set(newKey, updated.id)
      this.identities.set(updated.id, updated)
      return updated
    },
  }

  readonly verificationRepo: VerificationRepo = {
    findById: async (id) => this.verifications.get(id),
    create: async (verification) => {
      this.verifications.set(verification.id, verification)
      return verification
    },
    update: async (id, patch) => {
      const existing = this.verifications.get(id)

      if (!existing) {
        throw new UniAuthError(UniAuthErrorCode.VerificationNotFound, 'Verification was not found.')
      }

      const updated: Verification = { ...existing, ...patch }
      this.verifications.set(updated.id, updated)
      return updated
    },
  }

  readonly credentialRepo: CredentialRepo = {
    findPasswordByEmail: async (email) => {
      const id = this.credentialKeys.get(
        this.credentialKey(CredentialType.Password, normalizeEmail(email)),
      )
      return id ? this.credentials.get(id) : undefined
    },
    findPasswordByUserId: async (userId) => {
      const id = this.credentialUserKeys.get(
        this.credentialUserKey(CredentialType.Password, userId),
      )
      return id ? this.credentials.get(id) : undefined
    },
    listByUserId: async (userId) =>
      [...this.credentials.values()].filter((credential) => credential.userId === userId),
    create: async (credential) => {
      const key = this.credentialKey(credential.type, credential.subject)
      const userKey = this.credentialUserKey(credential.type, credential.userId)

      if (this.credentialKeys.has(key) || this.credentialUserKeys.has(userKey)) {
        throw new UniAuthError(
          UniAuthErrorCode.CredentialAlreadyExists,
          'Credential already exists.',
        )
      }

      this.credentials.set(credential.id, credential)
      this.credentialKeys.set(key, credential.id)
      this.credentialUserKeys.set(userKey, credential.id)
      return credential
    },
    update: async (id, patch) => {
      const existing = this.credentials.get(id)

      if (!existing) {
        throw new UniAuthError(UniAuthErrorCode.CredentialNotFound, 'Credential was not found.')
      }

      const updated: Credential = { ...existing, ...patch }
      const oldKey = this.credentialKey(existing.type, existing.subject)
      const newKey = this.credentialKey(updated.type, updated.subject)
      const oldUserKey = this.credentialUserKey(existing.type, existing.userId)
      const newUserKey = this.credentialUserKey(updated.type, updated.userId)
      const existingCredentialId = this.credentialKeys.get(newKey)
      const existingCredentialUserId = this.credentialUserKeys.get(newUserKey)

      if (
        (newKey !== oldKey && existingCredentialId) ||
        (newUserKey !== oldUserKey && existingCredentialUserId)
      ) {
        throw new UniAuthError(
          UniAuthErrorCode.CredentialAlreadyExists,
          'Credential already exists.',
        )
      }

      this.credentialKeys.delete(oldKey)
      this.credentialKeys.set(newKey, updated.id)
      this.credentialUserKeys.delete(oldUserKey)
      this.credentialUserKeys.set(newUserKey, updated.id)
      this.credentials.set(updated.id, updated)
      return updated
    },
  }

  readonly sessionRepo: SessionRepo = {
    findById: async (id) => this.sessions.get(id),
    listByUserId: async (userId) =>
      [...this.sessions.values()].filter((session) => session.userId === userId),
    create: async (session) => {
      this.sessions.set(session.id, session)
      return session
    },
    update: async (id, patch) => {
      const existing = this.sessions.get(id)

      if (!existing) {
        throw new UniAuthError(UniAuthErrorCode.SessionNotFound, 'Session was not found.')
      }

      const updated: Session = { ...existing, ...patch }
      this.sessions.set(updated.id, updated)
      return updated
    },
  }

  readonly auditLogRepo: AuditLogRepo = {
    append: async (event) => {
      this.auditEvents.push(event)
    },
  }

  async run<T>(operation: () => Promise<T>): Promise<T> {
    if (this.transactionDepth > 0) {
      return operation()
    }

    const snapshot = this.snapshot()
    this.transactionDepth += 1

    try {
      return await operation()
    } catch (error) {
      this.restore(snapshot)
      throw error
    } finally {
      this.transactionDepth -= 1
    }
  }

  listUsers(): readonly User[] {
    return [...this.users.values()]
  }

  listIdentities(): readonly AuthIdentity[] {
    return [...this.identities.values()]
  }

  listCredentials(): readonly Credential[] {
    return [...this.credentials.values()]
  }

  listSessions(): readonly Session[] {
    return [...this.sessions.values()]
  }

  listVerifications(): readonly Verification[] {
    return [...this.verifications.values()]
  }

  listAuditEvents(): readonly AuditEvent[] {
    return [...this.auditEvents]
  }

  private identityKey(provider: AuthIdentityProvider, providerUserId: string): string {
    return `${provider}\u0000${providerUserId}`
  }

  private credentialKey(type: CredentialType, subject: string): string {
    return `${type}\u0000${subject}`
  }

  private credentialUserKey(type: CredentialType, userId: User['id']): string {
    return `${type}\u0000${userId}`
  }

  private snapshot(): {
    readonly users: Map<User['id'], User>
    readonly identities: Map<AuthIdentity['id'], AuthIdentity>
    readonly identityKeys: Map<string, AuthIdentity['id']>
    readonly credentials: Map<Credential['id'], Credential>
    readonly credentialKeys: Map<string, Credential['id']>
    readonly credentialUserKeys: Map<string, Credential['id']>
    readonly verifications: Map<Verification['id'], Verification>
    readonly sessions: Map<Session['id'], Session>
    readonly auditEvents: AuditEvent[]
  } {
    return {
      users: new Map(this.users),
      identities: new Map(this.identities),
      identityKeys: new Map(this.identityKeys),
      credentials: new Map(this.credentials),
      credentialKeys: new Map(this.credentialKeys),
      credentialUserKeys: new Map(this.credentialUserKeys),
      verifications: new Map(this.verifications),
      sessions: new Map(this.sessions),
      auditEvents: [...this.auditEvents],
    }
  }

  private restore(snapshot: ReturnType<InMemoryAuthStore['snapshot']>): void {
    this.users.clear()
    this.identities.clear()
    this.identityKeys.clear()
    this.credentials.clear()
    this.credentialKeys.clear()
    this.credentialUserKeys.clear()
    this.verifications.clear()
    this.sessions.clear()
    this.auditEvents.length = 0

    for (const [id, user] of snapshot.users) {
      this.users.set(id, user)
    }

    for (const [id, identity] of snapshot.identities) {
      this.identities.set(id, identity)
    }

    for (const [key, id] of snapshot.identityKeys) {
      this.identityKeys.set(key, id)
    }

    for (const [id, credential] of snapshot.credentials) {
      this.credentials.set(id, credential)
    }

    for (const [key, id] of snapshot.credentialKeys) {
      this.credentialKeys.set(key, id)
    }

    for (const [key, id] of snapshot.credentialUserKeys) {
      this.credentialUserKeys.set(key, id)
    }

    for (const [id, verification] of snapshot.verifications) {
      this.verifications.set(id, verification)
    }

    for (const [id, session] of snapshot.sessions) {
      this.sessions.set(id, session)
    }

    this.auditEvents.push(...snapshot.auditEvents)
  }
}

export interface InMemoryEmailMessage {
  readonly to: string
  readonly subject: string
  readonly text: string
  readonly metadata?: Record<string, unknown>
}

export class InMemoryEmailSender implements EmailSender {
  private readonly messages: InMemoryEmailMessage[] = []

  async sendEmail(input: InMemoryEmailMessage): Promise<void> {
    this.messages.push(input)
  }

  listMessages(): readonly InMemoryEmailMessage[] {
    return [...this.messages]
  }
}

export interface InMemorySmsMessage {
  readonly to: string
  readonly text: string
  readonly metadata?: Record<string, unknown>
}

export class InMemorySmsSender implements SmsSender {
  private readonly messages: InMemorySmsMessage[] = []

  async sendSms(input: InMemorySmsMessage): Promise<void> {
    this.messages.push(input)
  }

  listMessages(): readonly InMemorySmsMessage[] {
    return [...this.messages]
  }
}

export class InMemoryRateLimiter implements RateLimiter {
  private readonly attempts: RateLimitAttempt[] = []
  private readonly decisions = new Map<string, RateLimitDecision>()

  async consume(input: RateLimitAttempt): Promise<RateLimitDecision> {
    this.attempts.push(input)
    return this.decisions.get(this.decisionKey(input.action, input.key)) ?? { allowed: true }
  }

  setDecision(input: Pick<RateLimitAttempt, 'action' | 'key'>, decision: RateLimitDecision): void {
    this.decisions.set(this.decisionKey(input.action, input.key), decision)
  }

  listAttempts(): readonly RateLimitAttempt[] {
    return [...this.attempts]
  }

  private decisionKey(action: RateLimitAttempt['action'], key: string): string {
    return `${action}\u0000${key}`
  }
}

export class InMemoryPasswordHasher implements PasswordHasher {
  async hash(password: string): Promise<string> {
    return `test-password:${hashSecret(password)}`
  }

  async verify(password: string, passwordHash: string): Promise<boolean> {
    return passwordHash === (await this.hash(password))
  }
}

export interface CreateInMemoryAuthKitOptions {
  readonly policy?: AuthPolicy
  readonly clock?: Clock
  readonly idGenerator?: IdGenerator
  readonly secretHasher?: SecretHasher
  readonly rateLimiter?: RateLimiter
  readonly otpSecretLength?: number
  readonly otpSecretGenerator?: OtpSecretGenerator
  readonly emailOtpSubject?: string
  readonly passwordHasher?: PasswordHasher
  readonly sessionTtlSeconds?: number
  readonly verificationTtlSeconds?: number
}

export function createInMemoryAuthKit(options: CreateInMemoryAuthKitOptions = {}): {
  readonly service: DefaultAuthService
  readonly store: InMemoryAuthStore
  readonly providerRegistry: InMemoryProviderRegistry
  readonly emailSender: InMemoryEmailSender
  readonly smsSender: InMemorySmsSender
  readonly rateLimiter: RateLimiter
  readonly passwordHasher: PasswordHasher
  readonly idGenerator: IdGenerator
} {
  const store = new InMemoryAuthStore()
  const providerRegistry = new InMemoryProviderRegistry()
  const emailSender = new InMemoryEmailSender()
  const smsSender = new InMemorySmsSender()
  const rateLimiter = options.rateLimiter ?? new InMemoryRateLimiter()
  const passwordHasher = options.passwordHasher ?? new InMemoryPasswordHasher()
  const idGenerator = options.idGenerator ?? createSequentialIdGenerator()
  const serviceOptions: DefaultAuthServiceOptions = {
    repos: store,
    emailSender,
    smsSender,
    rateLimiter,
    passwordHasher,
    providerRegistry,
    transaction: store,
    idGenerator,
    ...optionalProp('secretHasher', options.secretHasher),
    ...optionalProp('policy', options.policy),
    ...optionalProp('clock', options.clock),
    ...optionalProp('otpSecretLength', options.otpSecretLength),
    ...optionalProp('otpSecretGenerator', options.otpSecretGenerator),
    ...optionalProp('emailOtpSubject', options.emailOtpSubject),
    ...optionalProp('sessionTtlSeconds', options.sessionTtlSeconds),
    ...optionalProp('verificationTtlSeconds', options.verificationTtlSeconds),
  }

  return {
    service: createAuthService(serviceOptions),
    store,
    providerRegistry,
    emailSender,
    smsSender,
    rateLimiter,
    passwordHasher,
    idGenerator,
  }
}
