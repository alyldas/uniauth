import {
  createAuthService,
  type DefaultAuthService,
  type DefaultAuthServiceOptions,
} from '../application/auth-service.js'
import type { AuthPolicy } from '../application/policy.js'
import {
  AuthIdentityStatus,
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
import { UniauthError, UniauthErrorCode } from '../errors'
import type {
  AuditLogRepo,
  AuthServiceRepositories,
  CredentialRepo,
  EmailSender,
  IdentityRepo,
  SessionRepo,
  UnitOfWork,
  UserRepo,
  VerificationRepo,
} from '../ports'
import { createSequentialIdGenerator } from '../utils/ids.js'
import { normalizeEmail, normalizePhone } from '../utils/normalization.js'
import { InMemoryProviderRegistry } from './providers.js'

export class InMemoryAuthStore implements AuthServiceRepositories, UnitOfWork {
  private readonly users = new Map<User['id'], User>()
  private readonly identities = new Map<AuthIdentity['id'], AuthIdentity>()
  private readonly identityKeys = new Map<string, AuthIdentity['id']>()
  private readonly credentials = new Map<Credential['id'], Credential>()
  private readonly verifications = new Map<Verification['id'], Verification>()
  private readonly sessions = new Map<Session['id'], Session>()
  private readonly auditEvents: AuditEvent[] = []

  readonly userRepo: UserRepo = {
    findById: async (id) => this.users.get(id),
    create: async (user) => {
      this.users.set(user.id, user)
      return user
    },
    update: async (id, patch) => {
      const existing = this.users.get(id)

      if (!existing) {
        throw new UniauthError(UniauthErrorCode.UserNotFound, 'User was not found.')
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
        throw new UniauthError(UniauthErrorCode.IdentityAlreadyLinked, 'Identity cannot be linked.')
      }

      this.identities.set(identity.id, identity)
      this.identityKeys.set(key, identity.id)
      return identity
    },
    update: async (id, patch) => {
      const existing = this.identities.get(id)

      if (!existing) {
        throw new UniauthError(UniauthErrorCode.IdentityNotFound, 'Identity was not found.')
      }

      const updated: AuthIdentity = { ...existing, ...patch }
      const oldKey = this.identityKey(existing.provider, existing.providerUserId)
      const newKey = this.identityKey(updated.provider, updated.providerUserId)
      const existingIdentityId = this.identityKeys.get(newKey)

      if (newKey !== oldKey && existingIdentityId) {
        throw new UniauthError(UniauthErrorCode.IdentityAlreadyLinked, 'Identity cannot be linked.')
      }

      this.identityKeys.delete(oldKey)
      this.identityKeys.set(newKey, updated.id)
      this.identities.set(updated.id, updated)
      return updated
    },
  }

  readonly credentialRepo: CredentialRepo = {
    findById: async (id) => this.credentials.get(id),
    listByUserId: async (userId) =>
      [...this.credentials.values()].filter((credential) => credential.userId === userId),
    create: async (credential) => {
      this.credentials.set(credential.id, credential)
      return credential
    },
    update: async (id, patch) => {
      const existing = this.credentials.get(id)

      if (!existing) {
        throw new UniauthError(UniauthErrorCode.InvalidInput, 'Credential was not found.')
      }

      const updated: Credential = { ...existing, ...patch }
      this.credentials.set(updated.id, updated)
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
        throw new UniauthError(UniauthErrorCode.VerificationNotFound, 'Verification was not found.')
      }

      const updated: Verification = { ...existing, ...patch }
      this.verifications.set(updated.id, updated)
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
        throw new UniauthError(UniauthErrorCode.SessionNotFound, 'Session was not found.')
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
    return operation()
  }

  listUsers(): readonly User[] {
    return [...this.users.values()]
  }

  listIdentities(): readonly AuthIdentity[] {
    return [...this.identities.values()]
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

export interface CreateInMemoryAuthKitOptions {
  readonly policy?: AuthPolicy
  readonly clock?: Clock
  readonly idGenerator?: IdGenerator
  readonly sessionTtlSeconds?: number
  readonly verificationTtlSeconds?: number
}

export function createInMemoryAuthKit(options: CreateInMemoryAuthKitOptions = {}): {
  readonly service: DefaultAuthService
  readonly store: InMemoryAuthStore
  readonly providerRegistry: InMemoryProviderRegistry
  readonly emailSender: InMemoryEmailSender
  readonly idGenerator: IdGenerator
} {
  const store = new InMemoryAuthStore()
  const providerRegistry = new InMemoryProviderRegistry()
  const emailSender = new InMemoryEmailSender()
  const idGenerator = options.idGenerator ?? createSequentialIdGenerator()
  const serviceOptions: DefaultAuthServiceOptions = {
    repos: store,
    emailSender,
    providerRegistry,
    transaction: store,
    idGenerator,
    ...(options.policy ? { policy: options.policy } : {}),
    ...(options.clock ? { clock: options.clock } : {}),
    ...(options.sessionTtlSeconds ? { sessionTtlSeconds: options.sessionTtlSeconds } : {}),
    ...(options.verificationTtlSeconds
      ? { verificationTtlSeconds: options.verificationTtlSeconds }
      : {}),
  }

  return {
    service: createAuthService(serviceOptions),
    store,
    providerRegistry,
    emailSender,
    idGenerator,
  }
}
