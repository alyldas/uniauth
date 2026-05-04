import { getAccountInspectionSnapshot } from './account-inspection.js'
import { getAccountSecuritySnapshot } from './account-security.js'
import { getAuditEventPage, getAuditEvents } from './audit-events.js'
import { getUserIdentities, link, mergeAccounts, unlink } from './accounts.js'
import { getUserCredentials } from './credentials.js'
import {
  cancelEmailMagicLinkSignIn,
  finishEmailMagicLinkSignIn,
  resendEmailMagicLinkSignIn,
  startEmailMagicLinkSignIn,
} from './magic-link.js'
import {
  cancelOtpChallenge,
  finishOtpChallenge,
  finishOtpSignIn,
  resendOtpChallenge,
  startOtpChallenge,
} from './otp.js'
import {
  cancelEmailPasswordRecovery,
  changePassword,
  finishEmailPasswordRecovery,
  resendEmailPasswordRecovery,
  setPassword,
  signInWithPassword,
  startEmailPasswordRecovery,
} from './passwords.js'
import { type AuthServiceRuntime, createAuthServiceRuntime } from './runtime.js'
import { resolveSessionContext } from './session-context.js'
import {
  createSession,
  getUserSessions,
  resolveSession,
  revokeSession,
  revokeUserSessions,
  touchSession,
} from './sessions.js'
import { signIn } from './sign-in.js'
import { getUser } from './users.js'
import {
  cancelVerification,
  consumeVerification,
  createVerification,
  getVerification,
  getVerificationResendWindow,
} from './verifications.js'
import type { AuthPolicy } from './policy.js'
import type {
  AuthIdentity,
  AccountInspectionSnapshot,
  AccountSecuritySnapshot,
  AuditEvent,
  AuditEventPage,
  AuditEventQuery,
  AuthResult,
  AuthService,
  CancelEmailMagicLinkSignInInput,
  CancelEmailPasswordRecoveryInput,
  CancelOtpChallengeInput,
  CancelVerificationInput,
  ChangePasswordInput,
  Credential,
  ConsumeVerificationInput,
  CreateSessionInput,
  CreateSessionResult,
  CreateVerificationInput,
  CreateVerificationResult,
  FinishEmailMagicLinkSignInInput,
  FinishEmailPasswordRecoveryInput,
  FinishOtpChallengeInput,
  FinishOtpSignInInput,
  GetAccountInspectionSnapshotInput,
  GetVerificationResendWindowInput,
  LinkInput,
  LinkResult,
  MergeAccountsInput,
  MergeResult,
  RevokeUserSessionsInput,
  RevokeUserSessionsResult,
  ResendOtpChallengeInput,
  ResolveSessionContextInput,
  ResolveSessionInput,
  ResolvedSessionContext,
  Session,
  SessionId,
  SetPasswordInput,
  SignInInput,
  SignInWithPasswordInput,
  StartEmailMagicLinkSignInInput,
  StartEmailMagicLinkSignInResult,
  ResendEmailMagicLinkSignInInput,
  ResendEmailPasswordRecoveryInput,
  StartEmailPasswordRecoveryInput,
  StartEmailPasswordRecoveryResult,
  StartOtpChallengeInput,
  StartOtpChallengeResult,
  TouchSessionInput,
  UnlinkInput,
  User,
  UserId,
  Verification,
  VerificationResendWindow,
  VerificationId,
} from '../domain/types.js'
import type {
  AuthServiceInfrastructure,
  AuthServiceRepositories,
  Clock,
  IdGenerator,
  ProviderRegistry,
  UnitOfWork,
} from '../contracts.js'

export interface DefaultAuthServiceOptions extends AuthServiceInfrastructure {
  readonly repos: AuthServiceRepositories
  readonly policy?: AuthPolicy
  readonly providerRegistry?: ProviderRegistry | undefined
  readonly transaction?: UnitOfWork
  readonly idGenerator?: IdGenerator
  readonly clock?: Clock
  readonly sessionTtlSeconds?: number
  readonly verificationTtlSeconds?: number
  readonly verificationResendCooldownSeconds?: number
}

export class DefaultAuthService implements AuthService {
  private readonly runtime: AuthServiceRuntime

  constructor(options: DefaultAuthServiceOptions) {
    this.runtime = createAuthServiceRuntime(options)
  }

  async signIn(input: SignInInput): Promise<AuthResult> {
    return signIn(this.runtime, input)
  }

  async signInWithPassword(input: SignInWithPasswordInput): Promise<AuthResult> {
    return signInWithPassword(this.runtime, input)
  }

  async startOtpChallenge(input: StartOtpChallengeInput): Promise<StartOtpChallengeResult> {
    return startOtpChallenge(this.runtime, input)
  }

  async resendOtpChallenge(input: ResendOtpChallengeInput): Promise<StartOtpChallengeResult> {
    return resendOtpChallenge(this.runtime, input)
  }

  async cancelOtpChallenge(input: CancelOtpChallengeInput): Promise<Verification> {
    return cancelOtpChallenge(this.runtime, input)
  }

  async finishOtpChallenge(input: FinishOtpChallengeInput): Promise<Verification> {
    return finishOtpChallenge(this.runtime, input)
  }

  async finishOtpSignIn(input: FinishOtpSignInInput): Promise<AuthResult> {
    return finishOtpSignIn(this.runtime, input)
  }

  async startEmailMagicLinkSignIn(
    input: StartEmailMagicLinkSignInInput,
  ): Promise<StartEmailMagicLinkSignInResult> {
    return startEmailMagicLinkSignIn(this.runtime, input)
  }

  async resendEmailMagicLinkSignIn(
    input: ResendEmailMagicLinkSignInInput,
  ): Promise<StartEmailMagicLinkSignInResult> {
    return resendEmailMagicLinkSignIn(this.runtime, input)
  }

  async cancelEmailMagicLinkSignIn(input: CancelEmailMagicLinkSignInInput): Promise<Verification> {
    return cancelEmailMagicLinkSignIn(this.runtime, input)
  }

  async finishEmailMagicLinkSignIn(input: FinishEmailMagicLinkSignInInput): Promise<AuthResult> {
    return finishEmailMagicLinkSignIn(this.runtime, input)
  }

  async setPassword(input: SetPasswordInput): Promise<Credential> {
    return setPassword(this.runtime, input)
  }

  async changePassword(input: ChangePasswordInput): Promise<Credential> {
    return changePassword(this.runtime, input)
  }

  async startEmailPasswordRecovery(
    input: StartEmailPasswordRecoveryInput,
  ): Promise<StartEmailPasswordRecoveryResult> {
    return startEmailPasswordRecovery(this.runtime, input)
  }

  async resendEmailPasswordRecovery(
    input: ResendEmailPasswordRecoveryInput,
  ): Promise<StartEmailPasswordRecoveryResult> {
    return resendEmailPasswordRecovery(this.runtime, input)
  }

  async cancelEmailPasswordRecovery(
    input: CancelEmailPasswordRecoveryInput,
  ): Promise<Verification> {
    return cancelEmailPasswordRecovery(this.runtime, input)
  }

  async finishEmailPasswordRecovery(input: FinishEmailPasswordRecoveryInput): Promise<Credential> {
    return finishEmailPasswordRecovery(this.runtime, input)
  }

  async link(input: LinkInput): Promise<LinkResult> {
    return link(this.runtime, input)
  }

  async unlink(input: UnlinkInput): Promise<void> {
    return unlink(this.runtime, input)
  }

  async mergeAccounts(input: MergeAccountsInput): Promise<MergeResult> {
    return mergeAccounts(this.runtime, input)
  }

  async revokeSession(sessionId: SessionId): Promise<void> {
    return revokeSession(this.runtime, sessionId)
  }

  async revokeUserSessions(input: RevokeUserSessionsInput): Promise<RevokeUserSessionsResult> {
    return revokeUserSessions(this.runtime, input)
  }

  async resolveSession(input: ResolveSessionInput): Promise<Session> {
    return resolveSession(this.runtime, input)
  }

  async resolveSessionContext(input: ResolveSessionContextInput): Promise<ResolvedSessionContext> {
    return resolveSessionContext(this.runtime, input)
  }

  async touchSession(input: TouchSessionInput): Promise<Session> {
    return touchSession(this.runtime, input)
  }

  async getUser(userId: UserId): Promise<User> {
    return getUser(this.runtime, userId)
  }

  async getUserIdentities(userId: UserId): Promise<readonly AuthIdentity[]> {
    return getUserIdentities(this.runtime, userId)
  }

  async getUserCredentials(userId: UserId): Promise<readonly Credential[]> {
    return getUserCredentials(this.runtime, userId)
  }

  async getUserSessions(userId: UserId): Promise<readonly Session[]> {
    return getUserSessions(this.runtime, userId)
  }

  async getAuditEvents(input?: AuditEventQuery): Promise<readonly AuditEvent[]> {
    return getAuditEvents(this.runtime, input)
  }

  async getAuditEventPage(input?: AuditEventQuery): Promise<AuditEventPage> {
    return getAuditEventPage(this.runtime, input)
  }

  async getAccountSecuritySnapshot(userId: UserId): Promise<AccountSecuritySnapshot> {
    return getAccountSecuritySnapshot(this.runtime, userId)
  }

  async getAccountInspectionSnapshot(
    input: GetAccountInspectionSnapshotInput,
  ): Promise<AccountInspectionSnapshot> {
    return getAccountInspectionSnapshot(this.runtime, input)
  }

  async createSession(input: CreateSessionInput): Promise<CreateSessionResult> {
    return createSession(this.runtime, input)
  }

  async createVerification(input: CreateVerificationInput): Promise<CreateVerificationResult> {
    return createVerification(this.runtime, input)
  }

  async cancelVerification(input: CancelVerificationInput): Promise<Verification> {
    return cancelVerification(this.runtime, input)
  }

  async getVerification(verificationId: VerificationId): Promise<Verification> {
    return getVerification(this.runtime, verificationId)
  }

  async getVerificationResendWindow(
    input: GetVerificationResendWindowInput,
  ): Promise<VerificationResendWindow> {
    return getVerificationResendWindow(this.runtime, input)
  }

  async consumeVerification(input: ConsumeVerificationInput): Promise<Verification> {
    return consumeVerification(this.runtime, input)
  }
}

export function createAuthService(options: DefaultAuthServiceOptions): DefaultAuthService {
  return new DefaultAuthService(options)
}
