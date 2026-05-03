import type { AuthIdentity, Credential, Session, User, Verification } from './entities.js'
import type { AccountInspectionSnapshot, AccountSecuritySnapshot } from './views.js'
import type { AuditEvent, AuditEventPage, AuditEventQuery } from './audit.js'
import type {
  AuthResult,
  ConsumeVerificationInput,
  CreateSessionInput,
  CreateSessionResult,
  CreateVerificationInput,
  CreateVerificationResult,
  FinishOtpChallengeInput,
  FinishOtpSignInInput,
  GetAccountInspectionSnapshotInput,
  LinkInput,
  LinkResult,
  MergeAccountsInput,
  MergeResult,
  RevokeUserSessionsInput,
  RevokeUserSessionsResult,
  ResolveSessionContextInput,
  ResolveSessionInput,
  ResolvedSessionContext,
  SignInInput,
  StartOtpChallengeInput,
  StartOtpChallengeResult,
  TouchSessionInput,
  UnlinkInput,
} from './flows.js'
import type {
  AuditEventId,
  CredentialId,
  IdentityId,
  SessionId,
  UserId,
  VerificationId,
} from './ids.js'
import type {
  ChangePasswordInput,
  FinishEmailMagicLinkSignInInput,
  FinishEmailPasswordRecoveryInput,
  SetPasswordInput,
  SignInWithPasswordInput,
  StartEmailMagicLinkSignInInput,
  StartEmailMagicLinkSignInResult,
  StartEmailPasswordRecoveryInput,
  StartEmailPasswordRecoveryResult,
} from './local-auth.js'

export interface Clock {
  now(): Date
}

export interface IdGenerator {
  userId(): UserId
  identityId(): IdentityId
  credentialId(): CredentialId
  verificationId(): VerificationId
  sessionId(): SessionId
  auditEventId(): AuditEventId
}

export interface AuthService {
  signIn(input: SignInInput): Promise<AuthResult>
  signInWithPassword(input: SignInWithPasswordInput): Promise<AuthResult>
  startOtpChallenge(input: StartOtpChallengeInput): Promise<StartOtpChallengeResult>
  finishOtpChallenge(input: FinishOtpChallengeInput): Promise<Verification>
  finishOtpSignIn(input: FinishOtpSignInInput): Promise<AuthResult>
  startEmailMagicLinkSignIn(
    input: StartEmailMagicLinkSignInInput,
  ): Promise<StartEmailMagicLinkSignInResult>
  finishEmailMagicLinkSignIn(input: FinishEmailMagicLinkSignInInput): Promise<AuthResult>
  setPassword(input: SetPasswordInput): Promise<Credential>
  changePassword(input: ChangePasswordInput): Promise<Credential>
  startEmailPasswordRecovery(
    input: StartEmailPasswordRecoveryInput,
  ): Promise<StartEmailPasswordRecoveryResult>
  finishEmailPasswordRecovery(input: FinishEmailPasswordRecoveryInput): Promise<Credential>
  link(input: LinkInput): Promise<LinkResult>
  unlink(input: UnlinkInput): Promise<void>
  mergeAccounts(input: MergeAccountsInput): Promise<MergeResult>
  revokeSession(sessionId: SessionId): Promise<void>
  revokeUserSessions(input: RevokeUserSessionsInput): Promise<RevokeUserSessionsResult>
  resolveSession(input: ResolveSessionInput): Promise<Session>
  resolveSessionContext(input: ResolveSessionContextInput): Promise<ResolvedSessionContext>
  touchSession(input: TouchSessionInput): Promise<Session>
  getUser(userId: UserId): Promise<User>
  getUserIdentities(userId: UserId): Promise<readonly AuthIdentity[]>
  getUserCredentials(userId: UserId): Promise<readonly Credential[]>
  getUserSessions(userId: UserId): Promise<readonly Session[]>
  getAuditEvents(input?: AuditEventQuery): Promise<readonly AuditEvent[]>
  getAuditEventPage(input?: AuditEventQuery): Promise<AuditEventPage>
  getAccountSecuritySnapshot(userId: UserId): Promise<AccountSecuritySnapshot>
  getAccountInspectionSnapshot(
    input: GetAccountInspectionSnapshotInput,
  ): Promise<AccountInspectionSnapshot>
  createSession(input: CreateSessionInput): Promise<CreateSessionResult>
  createVerification(input: CreateVerificationInput): Promise<CreateVerificationResult>
  getVerification(verificationId: VerificationId): Promise<Verification>
  consumeVerification(input: ConsumeVerificationInput): Promise<Verification>
}
