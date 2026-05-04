import type { AuthIdentity, Credential, Session, User, Verification } from './entities.js'
import type {
  AccountInspectionSnapshot,
  AccountSecuritySnapshot,
  CurrentAccountInspectionSnapshot,
  CurrentAccountSecuritySnapshot,
  VerificationResendWindow,
} from './views.js'
import type { AuditEvent, AuditEventPage, AuditEventQuery } from './audit.js'
import type {
  AuthResult,
  GetCurrentAccountSecuritySnapshotInput,
  GetCurrentAccountAuditEventPageInput,
  GetCurrentAccountInspectionSnapshotInput,
  ConsumeVerificationInput,
  CancelOtpChallengeInput,
  CancelVerificationInput,
  CreateSessionInput,
  CreateSessionResult,
  CreateVerificationInput,
  CreateVerificationResult,
  FinishOtpChallengeInput,
  FinishOtpSignInInput,
  GetAccountInspectionSnapshotInput,
  StartCurrentAccountOtpReAuthInput,
  GetVerificationResendWindowInput,
  LinkInput,
  LinkResult,
  MergeAccountsInput,
  MergeResult,
  RevokeCurrentSessionByTokenInput,
  RevokeOwnedSessionByTokenInput,
  RevokeOwnedSessionByTokenResult,
  RevokeOtherSessionsByTokenInput,
  RevokeOtherSessionsByTokenResult,
  RevokeUserSessionsInput,
  RevokeUserSessionsResult,
  ResendOtpChallengeInput,
  ResolveSessionContextInput,
  ResolveSessionInput,
  ResolvedSessionContext,
  SignInInput,
  StartOtpChallengeInput,
  StartOtpChallengeResult,
  TouchSessionInput,
  UnlinkInput,
  UnlinkCurrentIdentityByTokenInput,
} from './flows.js'
import type { SessionId, UserId, VerificationId } from './ids.js'
import type {
  ChangePasswordInput,
  ChangeCurrentAccountPasswordByTokenInput,
  CancelEmailMagicLinkSignInInput,
  CancelEmailPasswordRecoveryInput,
  ConfirmCurrentAccountPasswordByTokenInput,
  CurrentAccountPasswordReAuthConfirmation,
  FinishEmailMagicLinkSignInInput,
  FinishEmailPasswordRecoveryInput,
  ResendEmailMagicLinkSignInInput,
  ResendEmailPasswordRecoveryInput,
  SetCurrentAccountPasswordByTokenInput,
  SetPasswordInput,
  SignInWithPasswordInput,
  StartEmailMagicLinkSignInInput,
  StartEmailMagicLinkSignInResult,
  StartEmailPasswordRecoveryInput,
  StartEmailPasswordRecoveryResult,
} from './local-auth.js'
export type { Clock, IdGenerator } from '../contracts.js'

export interface AuthService {
  signIn(input: SignInInput): Promise<AuthResult>
  signInWithPassword(input: SignInWithPasswordInput): Promise<AuthResult>
  startOtpChallenge(input: StartOtpChallengeInput): Promise<StartOtpChallengeResult>
  startCurrentAccountOtpReAuth(
    input: StartCurrentAccountOtpReAuthInput,
  ): Promise<StartOtpChallengeResult>
  resendOtpChallenge(input: ResendOtpChallengeInput): Promise<StartOtpChallengeResult>
  finishOtpChallenge(input: FinishOtpChallengeInput): Promise<Verification>
  finishOtpSignIn(input: FinishOtpSignInInput): Promise<AuthResult>
  startEmailMagicLinkSignIn(
    input: StartEmailMagicLinkSignInInput,
  ): Promise<StartEmailMagicLinkSignInResult>
  resendEmailMagicLinkSignIn(
    input: ResendEmailMagicLinkSignInInput,
  ): Promise<StartEmailMagicLinkSignInResult>
  finishEmailMagicLinkSignIn(input: FinishEmailMagicLinkSignInInput): Promise<AuthResult>
  setPassword(input: SetPasswordInput): Promise<Credential>
  changePassword(input: ChangePasswordInput): Promise<Credential>
  startEmailPasswordRecovery(
    input: StartEmailPasswordRecoveryInput,
  ): Promise<StartEmailPasswordRecoveryResult>
  resendEmailPasswordRecovery(
    input: ResendEmailPasswordRecoveryInput,
  ): Promise<StartEmailPasswordRecoveryResult>
  finishEmailPasswordRecovery(input: FinishEmailPasswordRecoveryInput): Promise<Credential>
  link(input: LinkInput): Promise<LinkResult>
  unlink(input: UnlinkInput): Promise<void>
  mergeAccounts(input: MergeAccountsInput): Promise<MergeResult>
  revokeSession(sessionId: SessionId): Promise<void>
  revokeUserSessions(input: RevokeUserSessionsInput): Promise<RevokeUserSessionsResult>
  resolveSession(input: ResolveSessionInput): Promise<Session>
  resolveSessionContext(input: ResolveSessionContextInput): Promise<ResolvedSessionContext>
  getCurrentAccountSecuritySnapshot(
    input: GetCurrentAccountSecuritySnapshotInput,
  ): Promise<CurrentAccountSecuritySnapshot>
  getCurrentAccountInspectionSnapshot(
    input: GetCurrentAccountInspectionSnapshotInput,
  ): Promise<CurrentAccountInspectionSnapshot>
  getCurrentAccountAuditEventPage(
    input: GetCurrentAccountAuditEventPageInput,
  ): Promise<AuditEventPage>
  revokeCurrentSessionByToken(input: RevokeCurrentSessionByTokenInput): Promise<void>
  revokeOwnedSessionByToken(
    input: RevokeOwnedSessionByTokenInput,
  ): Promise<RevokeOwnedSessionByTokenResult>
  revokeOtherSessionsByToken(
    input: RevokeOtherSessionsByTokenInput,
  ): Promise<RevokeOtherSessionsByTokenResult>
  unlinkCurrentIdentityByToken(input: UnlinkCurrentIdentityByTokenInput): Promise<void>
  setCurrentAccountPasswordByToken(
    input: SetCurrentAccountPasswordByTokenInput,
  ): Promise<Credential>
  confirmCurrentAccountPasswordByToken(
    input: ConfirmCurrentAccountPasswordByTokenInput,
  ): Promise<CurrentAccountPasswordReAuthConfirmation>
  changeCurrentAccountPasswordByToken(
    input: ChangeCurrentAccountPasswordByTokenInput,
  ): Promise<Credential>
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
  cancelVerification(input: CancelVerificationInput): Promise<Verification>
  getVerification(verificationId: VerificationId): Promise<Verification>
  getVerificationResendWindow(
    input: GetVerificationResendWindowInput,
  ): Promise<VerificationResendWindow>
  consumeVerification(input: ConsumeVerificationInput): Promise<Verification>
  cancelOtpChallenge(input: CancelOtpChallengeInput): Promise<Verification>
  cancelEmailMagicLinkSignIn(input: CancelEmailMagicLinkSignInInput): Promise<Verification>
  cancelEmailPasswordRecovery(input: CancelEmailPasswordRecoveryInput): Promise<Verification>
}
