import type {
  AuditEvent,
  AuthIdentity,
  AuthIdentityProvider,
  Credential,
  CredentialId,
  IdentityId,
  Session,
  SessionId,
  User,
  UserId,
  Verification,
  VerificationId,
} from '../domain/types.js'

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

export interface AuthServiceRepositories {
  readonly userRepo: UserRepo
  readonly identityRepo: IdentityRepo
  readonly credentialRepo: CredentialRepo
  readonly verificationRepo: VerificationRepo
  readonly sessionRepo: SessionRepo
  readonly auditLogRepo: AuditLogRepo
}
