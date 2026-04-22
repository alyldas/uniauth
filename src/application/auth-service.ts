import {
  AuthIdentityStatus,
  EMAIL_OTP_PROVIDER_ID,
  SessionStatus,
  type AuditEvent,
  type AuditEventType,
  type AuthIdentity,
  type AuthResult,
  type AuthService,
  type Clock,
  type ConsumeVerificationInput,
  type CreateSessionInput,
  type CreateVerificationInput,
  type CreateVerificationResult,
  type FinishEmailOtpSignInInput,
  type FinishInput,
  type IdGenerator,
  type IdentityId,
  type LinkInput,
  type LinkResult,
  type MergeAccountsInput,
  type MergeResult,
  type ProviderIdentityAssertion,
  type Session,
  type SessionId,
  type SignInInput,
  type StartEmailOtpSignInInput,
  type StartEmailOtpSignInResult,
  type UnlinkInput,
  type User,
  type UserId,
  type Verification,
  VerificationPurpose,
  VerificationStatus,
} from '../domain/types.js'
import { UniauthError, UniauthErrorCode, invalidInput } from '../errors'
import type { AuthPolicy, AuthPolicyAction } from './policy.js'
import { defaultAuthPolicy } from './policy.js'
import type {
  AuthServiceInfrastructure,
  AuthServiceRepositories,
  EmailSender,
  ProviderRegistry,
  UnitOfWork,
} from '../ports'
import { createRandomIdGenerator } from '../utils/ids.js'
import { normalizeEmail, normalizePhone, normalizeTarget } from '../utils/normalization.js'
import { generateOtpSecret, generateSecret, hashSecret, verifySecret } from '../utils/secrets.js'
import { addSeconds, systemClock } from '../utils/time.js'

const DEFAULT_SESSION_TTL_SECONDS = 60 * 60 * 24 * 30
const DEFAULT_VERIFICATION_TTL_SECONDS = 60 * 10
const DEFAULT_EMAIL_OTP_SUBJECT = 'Your sign-in code'

const immediateUnitOfWork: UnitOfWork = {
  run: (operation) => operation(),
}

export interface DefaultAuthServiceOptions extends AuthServiceInfrastructure {
  readonly repos: AuthServiceRepositories
  readonly policy?: AuthPolicy
  readonly providerRegistry?: ProviderRegistry | undefined
  readonly transaction?: UnitOfWork
  readonly idGenerator?: IdGenerator
  readonly clock?: Clock
  readonly sessionTtlSeconds?: number
  readonly verificationTtlSeconds?: number
}

export class DefaultAuthService implements AuthService {
  private readonly repos: AuthServiceRepositories
  private readonly emailSender: EmailSender | undefined
  private readonly policy: AuthPolicy
  private readonly providerRegistry: ProviderRegistry | undefined
  private readonly transaction: UnitOfWork
  private readonly idGenerator: IdGenerator
  private readonly clock: Clock
  private readonly sessionTtlSeconds: number
  private readonly verificationTtlSeconds: number

  constructor(options: DefaultAuthServiceOptions) {
    this.repos = options.repos
    this.emailSender = options.emailSender
    this.policy = options.policy ?? defaultAuthPolicy
    this.providerRegistry = options.providerRegistry
    this.transaction = options.transaction ?? immediateUnitOfWork
    this.idGenerator = options.idGenerator ?? createRandomIdGenerator()
    this.clock = options.clock ?? systemClock
    this.sessionTtlSeconds = options.sessionTtlSeconds ?? DEFAULT_SESSION_TTL_SECONDS
    this.verificationTtlSeconds = options.verificationTtlSeconds ?? DEFAULT_VERIFICATION_TTL_SECONDS
  }

  async signIn(input: SignInInput): Promise<AuthResult> {
    return this.transaction.run(async () => {
      const now = input.now ?? this.clock.now()
      const assertion = await this.resolveAssertion(input)
      return this.signInWithAssertion(assertion, {
        now,
        ...(input.sessionExpiresAt ? { sessionExpiresAt: input.sessionExpiresAt } : {}),
        ...(input.metadata ? { metadata: input.metadata } : {}),
      })
    })
  }

  async startEmailOtpSignIn(input: StartEmailOtpSignInInput): Promise<StartEmailOtpSignInResult> {
    const email = normalizeEmail(input.email)

    if (!email) {
      throw invalidInput('Email is required.')
    }

    if (!this.emailSender) {
      throw invalidInput('Email sender is required for email OTP sign-in.')
    }

    const created = await this.createVerification({
      purpose: VerificationPurpose.SignIn,
      target: email,
      secret: input.secret ?? generateOtpSecret(),
      ...(input.ttlSeconds ? { ttlSeconds: input.ttlSeconds } : {}),
      ...(input.now ? { now: input.now } : {}),
      metadata: {
        ...input.metadata,
        channel: 'email',
        provider: EMAIL_OTP_PROVIDER_ID,
      },
    })

    await this.emailSender.sendEmail({
      to: created.verification.target,
      subject: DEFAULT_EMAIL_OTP_SUBJECT,
      text: `Your sign-in code is ${created.secret}.`,
      metadata: {
        verificationId: created.verification.id,
        purpose: created.verification.purpose,
        delivery: 'email',
      },
    })

    return {
      verificationId: created.verification.id,
      expiresAt: created.verification.expiresAt,
      delivery: 'email',
    }
  }

  async finishEmailOtpSignIn(input: FinishEmailOtpSignInInput): Promise<AuthResult> {
    return this.transaction.run(async () => {
      const now = input.now ?? this.clock.now()
      const verification = await this.repos.verificationRepo.findById(input.verificationId)

      if (!verification) {
        throw new UniauthError(UniauthErrorCode.VerificationNotFound, 'Verification was not found.')
      }

      if (verification.purpose !== VerificationPurpose.SignIn) {
        throw invalidInput('Verification cannot be used for email OTP sign-in.')
      }

      const consumed = await this.consumeVerificationRecord({
        verificationId: input.verificationId,
        secret: input.secret,
        now,
      })

      return this.signInWithAssertion(
        this.normalizeAssertion({
          provider: EMAIL_OTP_PROVIDER_ID,
          providerUserId: consumed.target,
          email: consumed.target,
          emailVerified: true,
        }),
        {
          now,
          ...(input.sessionExpiresAt ? { sessionExpiresAt: input.sessionExpiresAt } : {}),
          ...(input.metadata ? { metadata: input.metadata } : {}),
        },
      )
    })
  }

  async link(input: LinkInput): Promise<LinkResult> {
    return this.transaction.run(async () => {
      const now = input.now ?? this.clock.now()
      const user = await this.getActiveUser(input.userId)
      await this.ensureReAuth('link', user.id, input.reAuthenticatedAt, now)

      const assertion = await this.resolveAssertion(input)
      const exactIdentity = await this.repos.identityRepo.findByProviderUserId(
        assertion.provider,
        assertion.providerUserId,
      )

      if (exactIdentity && this.isActiveIdentity(exactIdentity)) {
        if (exactIdentity.userId === user.id) {
          return { user, identity: exactIdentity, linked: false }
        }

        await this.audit('auth.policy_denied', now, {
          userId: user.id,
          identityId: exactIdentity.id,
          metadata: { reason: 'identity-already-linked' },
        })
        throw new UniauthError(UniauthErrorCode.IdentityAlreadyLinked, 'Identity cannot be linked.')
      }

      const identity = await this.createIdentityFromAssertion(user, assertion, now)
      await this.audit('auth.identity_linked', now, {
        userId: user.id,
        identityId: identity.id,
        ...(input.metadata ? { metadata: input.metadata } : {}),
      })

      return { user, identity, linked: true }
    })
  }

  async unlink(input: UnlinkInput): Promise<void> {
    await this.transaction.run(async () => {
      const now = input.now ?? this.clock.now()
      const user = await this.getActiveUser(input.userId)
      await this.ensureReAuth('unlink', user.id, input.reAuthenticatedAt, now)

      const identity = await this.getActiveIdentity(input.identityId)

      if (identity.userId !== user.id) {
        throw new UniauthError(UniauthErrorCode.IdentityNotFound, 'Identity was not found.')
      }

      const activeIdentities = (await this.repos.identityRepo.listByUserId(user.id)).filter(
        (item) => this.isActiveIdentity(item),
      )
      const allowed = await this.policy.canUnlinkIdentity({
        user,
        identity,
        activeIdentityCount: activeIdentities.length,
      })

      if (!allowed) {
        await this.audit('auth.policy_denied', now, {
          userId: user.id,
          identityId: identity.id,
          metadata: { reason: 'unlink-denied' },
        })
        const code =
          activeIdentities.length <= 1
            ? UniauthErrorCode.LastIdentity
            : UniauthErrorCode.PolicyDenied
        const message =
          activeIdentities.length <= 1
            ? 'Cannot unlink the last active identity.'
            : 'Auth policy denied this action.'
        throw new UniauthError(code, message)
      }

      await this.repos.identityRepo.update(identity.id, {
        status: AuthIdentityStatus.Disabled,
        disabledAt: now,
        updatedAt: now,
      })
      await this.audit('auth.identity_unlinked', now, {
        userId: user.id,
        identityId: identity.id,
        ...(input.metadata ? { metadata: input.metadata } : {}),
      })
    })
  }

  async mergeAccounts(input: MergeAccountsInput): Promise<MergeResult> {
    return this.transaction.run(async () => {
      const now = input.now ?? this.clock.now()
      const sourceUser = await this.getActiveUser(input.sourceUserId)
      const targetUser = await this.getActiveUser(input.targetUserId)

      if (sourceUser.id === targetUser.id) {
        throw invalidInput('Source and target users must be different.')
      }

      await this.ensureReAuth('mergeAccounts', targetUser.id, input.reAuthenticatedAt, now)

      const sourceIdentities = (await this.repos.identityRepo.listByUserId(sourceUser.id)).filter(
        (identity) => this.isActiveIdentity(identity),
      )
      const allowed = await this.policy.canMergeUsers({
        sourceUser,
        targetUser,
        sourceIdentityCount: sourceIdentities.length,
      })

      if (!allowed) {
        await this.audit('auth.policy_denied', now, {
          userId: targetUser.id,
          metadata: { reason: 'merge-denied', sourceUserId: sourceUser.id },
        })
        throw new UniauthError(UniauthErrorCode.PolicyDenied, 'Auth policy denied this action.')
      }

      const movedIdentityIds: IdentityId[] = []

      for (const identity of sourceIdentities) {
        await this.repos.identityRepo.update(identity.id, {
          userId: targetUser.id,
          updatedAt: now,
        })
        movedIdentityIds.push(identity.id)
      }

      const disabledSourceUser = await this.repos.userRepo.update(sourceUser.id, {
        disabledAt: now,
        updatedAt: now,
      })

      const sourceSessions = await this.repos.sessionRepo.listByUserId(sourceUser.id)

      for (const session of sourceSessions) {
        if (session.status === SessionStatus.Active) {
          await this.repos.sessionRepo.update(session.id, {
            status: SessionStatus.Revoked,
            revokedAt: now,
          })
        }
      }

      await this.audit('auth.accounts_merged', now, {
        userId: targetUser.id,
        metadata: { sourceUserId: sourceUser.id, movedIdentityIds },
      })

      return {
        sourceUser: disabledSourceUser,
        targetUser,
        movedIdentityIds,
      }
    })
  }

  async revokeSession(sessionId: SessionId): Promise<void> {
    await this.transaction.run(async () => {
      const now = this.clock.now()
      const session = await this.repos.sessionRepo.findById(sessionId)

      if (!session) {
        throw new UniauthError(UniauthErrorCode.SessionNotFound, 'Session was not found.')
      }

      await this.repos.sessionRepo.update(session.id, {
        status: SessionStatus.Revoked,
        revokedAt: now,
      })
      await this.audit('auth.session_revoked', now, {
        userId: session.userId,
        sessionId: session.id,
      })
    })
  }

  async getUserIdentities(userId: UserId): Promise<readonly AuthIdentity[]> {
    await this.getActiveUser(userId)
    return this.repos.identityRepo.listByUserId(userId)
  }

  async createSession(input: CreateSessionInput): Promise<Session> {
    return this.transaction.run(async () => {
      const now = input.now ?? this.clock.now()
      await this.getActiveUser(input.userId)
      return this.createSessionRecord({ ...input, now })
    })
  }

  async createVerification(input: CreateVerificationInput): Promise<CreateVerificationResult> {
    return this.transaction.run(async () => {
      const now = input.now ?? this.clock.now()
      const secret = input.secret ?? generateSecret()
      const verification: Verification = {
        id: this.idGenerator.verificationId(),
        purpose: input.purpose,
        target: normalizeTarget(input.target),
        secretHash: hashSecret(secret),
        status: VerificationStatus.Pending,
        createdAt: now,
        expiresAt: addSeconds(now, input.ttlSeconds ?? this.verificationTtlSeconds),
        ...(input.metadata ? { metadata: input.metadata } : {}),
      }

      const created = await this.repos.verificationRepo.create(verification)
      await this.audit('auth.verification_created', now, {
        metadata: { verificationId: created.id, purpose: created.purpose },
      })

      return { verification: created, secret }
    })
  }

  async consumeVerification(input: ConsumeVerificationInput): Promise<Verification> {
    return this.transaction.run(async () => {
      return this.consumeVerificationRecord(input)
    })
  }

  private async signInWithAssertion(
    assertion: ProviderIdentityAssertion,
    input: {
      readonly now: Date
      readonly sessionExpiresAt?: Date
      readonly metadata?: Record<string, unknown>
    },
  ): Promise<AuthResult> {
    const exactIdentity = await this.repos.identityRepo.findByProviderUserId(
      assertion.provider,
      assertion.providerUserId,
    )

    if (exactIdentity && this.isActiveIdentity(exactIdentity)) {
      const user = await this.getActiveUser(exactIdentity.userId)
      const session = await this.createSessionRecord({
        userId: user.id,
        now: input.now,
        ...(input.sessionExpiresAt ? { expiresAt: input.sessionExpiresAt } : {}),
        ...(input.metadata ? { metadata: input.metadata } : {}),
      })
      await this.audit('auth.sign_in', input.now, {
        userId: user.id,
        identityId: exactIdentity.id,
        sessionId: session.id,
        metadata: { mode: 'exact' },
      })

      return {
        user,
        identity: exactIdentity,
        session,
        isNewUser: false,
        isNewIdentity: false,
      }
    }

    const autoLinkTarget = await this.findAutoLinkTarget(assertion)

    if (autoLinkTarget) {
      const identity = await this.createIdentityFromAssertion(autoLinkTarget, assertion, input.now)
      const session = await this.createSessionRecord({
        userId: autoLinkTarget.id,
        now: input.now,
        ...(input.sessionExpiresAt ? { expiresAt: input.sessionExpiresAt } : {}),
        ...(input.metadata ? { metadata: input.metadata } : {}),
      })
      await this.audit('auth.identity_linked', input.now, {
        userId: autoLinkTarget.id,
        identityId: identity.id,
        metadata: { mode: 'auto-link' },
      })
      await this.audit('auth.sign_in', input.now, {
        userId: autoLinkTarget.id,
        identityId: identity.id,
        sessionId: session.id,
        metadata: { mode: 'auto-link' },
      })

      return {
        user: autoLinkTarget,
        identity,
        session,
        isNewUser: false,
        isNewIdentity: true,
      }
    }

    const user = await this.createUserFromAssertion(assertion, input.now)
    const identity = await this.createIdentityFromAssertion(user, assertion, input.now)
    const session = await this.createSessionRecord({
      userId: user.id,
      now: input.now,
      ...(input.sessionExpiresAt ? { expiresAt: input.sessionExpiresAt } : {}),
      ...(input.metadata ? { metadata: input.metadata } : {}),
    })
    await this.audit('auth.sign_in', input.now, {
      userId: user.id,
      identityId: identity.id,
      sessionId: session.id,
      metadata: { mode: 'new-user' },
    })

    return {
      user,
      identity,
      session,
      isNewUser: true,
      isNewIdentity: true,
    }
  }

  private async consumeVerificationRecord(input: ConsumeVerificationInput): Promise<Verification> {
    const now = input.now ?? this.clock.now()
    const verification = await this.repos.verificationRepo.findById(input.verificationId)

    if (!verification) {
      throw new UniauthError(UniauthErrorCode.VerificationNotFound, 'Verification was not found.')
    }

    if (verification.status === VerificationStatus.Consumed) {
      throw new UniauthError(
        UniauthErrorCode.VerificationConsumed,
        'Verification has already been consumed.',
      )
    }

    if (verification.expiresAt.getTime() <= now.getTime()) {
      throw new UniauthError(UniauthErrorCode.VerificationExpired, 'Verification has expired.')
    }

    if (!verifySecret(input.secret, verification.secretHash)) {
      throw new UniauthError(
        UniauthErrorCode.VerificationInvalidSecret,
        'Verification secret is invalid.',
      )
    }

    const consumed = await this.repos.verificationRepo.update(verification.id, {
      status: VerificationStatus.Consumed,
      consumedAt: now,
    })
    await this.audit('auth.verification_consumed', now, {
      metadata: { verificationId: consumed.id, purpose: consumed.purpose },
    })

    return consumed
  }

  private async resolveAssertion(input: {
    readonly assertion?: ProviderIdentityAssertion
    readonly provider?: string
    readonly finishInput?: FinishInput
  }): Promise<ProviderIdentityAssertion> {
    if (input.assertion) {
      return this.normalizeAssertion(input.assertion)
    }

    if (!input.provider || !input.finishInput) {
      throw invalidInput('Either assertion or provider finish input is required.')
    }

    if (!this.providerRegistry) {
      throw new UniauthError(UniauthErrorCode.ProviderNotFound, 'Auth provider was not found.')
    }

    const provider = await this.providerRegistry.get(input.provider)

    if (!provider) {
      throw new UniauthError(UniauthErrorCode.ProviderNotFound, 'Auth provider was not found.')
    }

    return this.normalizeAssertion(await provider.finish(input.finishInput))
  }

  private normalizeAssertion(assertion: ProviderIdentityAssertion): ProviderIdentityAssertion {
    const provider = assertion.provider.trim()
    const providerUserId = assertion.providerUserId.trim()

    if (!provider || !providerUserId) {
      throw invalidInput('Provider and provider user id are required.')
    }

    return {
      provider,
      providerUserId,
      ...(assertion.email
        ? {
            email: normalizeEmail(assertion.email),
            emailVerified: assertion.emailVerified === true,
          }
        : {}),
      ...(assertion.phone
        ? {
            phone: normalizePhone(assertion.phone),
            phoneVerified: assertion.phoneVerified === true,
          }
        : {}),
      ...(assertion.displayName ? { displayName: assertion.displayName.trim() } : {}),
      ...(assertion.metadata ? { metadata: assertion.metadata } : {}),
      ...(assertion.rawProfile ? { rawProfile: assertion.rawProfile } : {}),
    }
  }

  private async findAutoLinkTarget(
    assertion: ProviderIdentityAssertion,
  ): Promise<User | undefined> {
    const candidateIdentities = new Map<string, AuthIdentity>()

    if (assertion.email && assertion.emailVerified === true) {
      for (const identity of await this.repos.identityRepo.findByVerifiedEmail(assertion.email)) {
        if (this.isActiveIdentity(identity)) {
          candidateIdentities.set(identity.id, identity)
        }
      }
    }

    if (assertion.phone && assertion.phoneVerified === true) {
      for (const identity of await this.repos.identityRepo.findByVerifiedPhone(assertion.phone)) {
        if (this.isActiveIdentity(identity)) {
          candidateIdentities.set(identity.id, identity)
        }
      }
    }

    const identities = [...candidateIdentities.values()]
    const userIds = [...new Set(identities.map((identity) => identity.userId))]

    if (userIds.length !== 1) {
      return undefined
    }

    const userId = userIds[0]

    if (!userId) {
      return undefined
    }

    const targetUser = await this.repos.userRepo.findById(userId)

    if (!targetUser || targetUser.disabledAt) {
      return undefined
    }

    const allowed = await this.policy.canAutoLink({
      assertion,
      targetUser,
      existingIdentities: identities,
    })

    return allowed ? targetUser : undefined
  }

  private async createUserFromAssertion(
    assertion: ProviderIdentityAssertion,
    now: Date,
  ): Promise<User> {
    const user: User = {
      id: this.idGenerator.userId(),
      createdAt: now,
      updatedAt: now,
      ...(assertion.displayName ? { displayName: assertion.displayName } : {}),
      ...(assertion.email && assertion.emailVerified === true ? { email: assertion.email } : {}),
      ...(assertion.phone && assertion.phoneVerified === true ? { phone: assertion.phone } : {}),
    }

    return this.repos.userRepo.create(user)
  }

  private async createIdentityFromAssertion(
    user: User,
    assertion: ProviderIdentityAssertion,
    now: Date,
  ): Promise<AuthIdentity> {
    const identity: AuthIdentity = {
      id: this.idGenerator.identityId(),
      userId: user.id,
      provider: assertion.provider,
      providerUserId: assertion.providerUserId,
      status: AuthIdentityStatus.Active,
      createdAt: now,
      updatedAt: now,
      ...(assertion.email
        ? { email: assertion.email, emailVerified: assertion.emailVerified === true }
        : {}),
      ...(assertion.phone
        ? { phone: assertion.phone, phoneVerified: assertion.phoneVerified === true }
        : {}),
      ...(assertion.metadata ? { metadata: assertion.metadata } : {}),
    }

    return this.repos.identityRepo.create(identity)
  }

  private async createSessionRecord(
    input: CreateSessionInput & { readonly now: Date },
  ): Promise<Session> {
    const session: Session = {
      id: this.idGenerator.sessionId(),
      userId: input.userId,
      status: SessionStatus.Active,
      createdAt: input.now,
      expiresAt: input.expiresAt ?? addSeconds(input.now, this.sessionTtlSeconds),
      ...(input.metadata ? { metadata: input.metadata } : {}),
    }

    const created = await this.repos.sessionRepo.create(session)
    await this.audit('auth.session_created', input.now, {
      userId: created.userId,
      sessionId: created.id,
    })

    return created
  }

  private async ensureReAuth(
    action: AuthPolicyAction,
    userId: UserId,
    reAuthenticatedAt: Date | undefined,
    now: Date,
  ): Promise<void> {
    const required = await this.policy.requiresReAuth({ action, userId, reAuthenticatedAt, now })

    if (required) {
      await this.audit('auth.policy_denied', now, {
        userId,
        metadata: { reason: 're-auth-required', action },
      })
      throw new UniauthError(UniauthErrorCode.ReAuthRequired, 'Recent authentication is required.')
    }
  }

  private async getActiveUser(userId: UserId): Promise<User> {
    const user = await this.repos.userRepo.findById(userId)

    if (!user || user.disabledAt) {
      throw new UniauthError(UniauthErrorCode.UserNotFound, 'User was not found.')
    }

    return user
  }

  private async getActiveIdentity(identityId: IdentityId): Promise<AuthIdentity> {
    const identity = await this.repos.identityRepo.findById(identityId)

    if (!identity || !this.isActiveIdentity(identity)) {
      throw new UniauthError(UniauthErrorCode.IdentityNotFound, 'Identity was not found.')
    }

    return identity
  }

  private isActiveIdentity(identity: AuthIdentity): boolean {
    return identity.status === AuthIdentityStatus.Active && !identity.disabledAt
  }

  private async audit(
    type: AuditEventType,
    occurredAt: Date,
    input: {
      readonly userId?: UserId
      readonly identityId?: IdentityId
      readonly sessionId?: SessionId
      readonly metadata?: Record<string, unknown>
    } = {},
  ): Promise<void> {
    const event: AuditEvent = {
      id: this.idGenerator.auditEventId(),
      type,
      occurredAt,
      ...(input.userId ? { userId: input.userId } : {}),
      ...(input.identityId ? { identityId: input.identityId } : {}),
      ...(input.sessionId ? { sessionId: input.sessionId } : {}),
      ...(input.metadata ? { metadata: input.metadata } : {}),
    }

    await this.repos.auditLogRepo.append(event)
  }
}

export function createAuthService(options: DefaultAuthServiceOptions): DefaultAuthService {
  return new DefaultAuthService(options)
}
