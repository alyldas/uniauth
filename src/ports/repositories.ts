import type {
  AuditEvent,
  AuditEventQuery,
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

export interface UserUpdatePatch {
  readonly displayName?: User['displayName'] | undefined
  readonly email?: User['email'] | undefined
  readonly phone?: User['phone'] | undefined
  readonly updatedAt?: User['updatedAt']
  readonly disabledAt?: User['disabledAt'] | undefined
  readonly metadata?: User['metadata'] | undefined
}

export interface IdentityUpdatePatch {
  readonly userId?: AuthIdentity['userId']
  readonly provider?: AuthIdentity['provider']
  readonly providerUserId?: AuthIdentity['providerUserId']
  readonly status?: AuthIdentity['status']
  readonly email?: AuthIdentity['email'] | undefined
  readonly emailVerified?: AuthIdentity['emailVerified'] | undefined
  readonly phone?: AuthIdentity['phone'] | undefined
  readonly phoneVerified?: AuthIdentity['phoneVerified'] | undefined
  readonly trust?: AuthIdentity['trust'] | undefined
  readonly updatedAt?: AuthIdentity['updatedAt']
  readonly disabledAt?: AuthIdentity['disabledAt'] | undefined
  readonly metadata?: AuthIdentity['metadata'] | undefined
}

export interface CredentialUpdatePatch {
  readonly userId?: Credential['userId']
  readonly subject?: Credential['subject']
  readonly passwordHash?: Credential['passwordHash']
  readonly updatedAt?: Credential['updatedAt']
  readonly metadata?: Credential['metadata'] | undefined
}

export interface VerificationUpdatePatch {
  readonly purpose?: Verification['purpose']
  readonly target?: Verification['target']
  readonly provider?: Verification['provider'] | undefined
  readonly channel?: Verification['channel'] | undefined
  readonly secretHash?: Verification['secretHash']
  readonly status?: Verification['status']
  readonly expiresAt?: Verification['expiresAt']
  readonly consumedAt?: Verification['consumedAt'] | undefined
  readonly metadata?: Verification['metadata'] | undefined
}

export interface SessionUpdatePatch {
  readonly userId?: Session['userId']
  readonly tokenHash?: Session['tokenHash']
  readonly status?: Session['status']
  readonly expiresAt?: Session['expiresAt']
  readonly revokedAt?: Session['revokedAt'] | undefined
  readonly lastSeenAt?: Session['lastSeenAt'] | undefined
  readonly metadata?: Session['metadata'] | undefined
}

export interface UserRepo {
  findById(id: UserId): Promise<User | undefined>
  create(user: User): Promise<User>
  update(id: UserId, patch: UserUpdatePatch): Promise<User>
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
  update(id: IdentityId, patch: IdentityUpdatePatch): Promise<AuthIdentity>
}

export interface CredentialRepo {
  findPasswordByEmail(email: string): Promise<Credential | undefined>
  findPasswordByUserId(userId: UserId): Promise<Credential | undefined>
  listByUserId(userId: UserId): Promise<readonly Credential[]>
  create(credential: Credential): Promise<Credential>
  update(id: CredentialId, patch: CredentialUpdatePatch): Promise<Credential>
}

export interface VerificationRepo {
  findById(id: VerificationId): Promise<Verification | undefined>
  findByIdForUpdate(id: VerificationId): Promise<Verification | undefined>
  create(verification: Verification): Promise<Verification>
  update(id: VerificationId, patch: VerificationUpdatePatch): Promise<Verification>
}

export interface SessionRepo {
  findById(id: SessionId): Promise<Session | undefined>
  findByTokenHash(tokenHash: string): Promise<Session | undefined>
  listByUserId(userId: UserId): Promise<readonly Session[]>
  create(session: Session): Promise<Session>
  update(id: SessionId, patch: SessionUpdatePatch): Promise<Session>
}

export interface AuditLogRepo {
  append(event: AuditEvent): Promise<void>
  list(input?: AuditEventQuery): Promise<readonly AuditEvent[]>
}

export interface AuthServiceRepositories {
  readonly userRepo: UserRepo
  readonly identityRepo: IdentityRepo
  readonly credentialRepo: CredentialRepo
  readonly verificationRepo: VerificationRepo
  readonly sessionRepo: SessionRepo
  readonly auditLogRepo: AuditLogRepo
}
