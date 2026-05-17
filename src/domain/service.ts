import type { AuthIdentity, Credential, Session, User, Verification } from './entities.js'
import type {
  AccountInspectionSnapshot,
  AuditEventView,
  AccountSecurityCredentialView,
  AccountSecurityIdentityView,
  AccountSecuritySessionView,
  AccountSecurityUserView,
  AccountSecuritySnapshot,
  CurrentAccountClosureExportSnapshot,
  CurrentAccountInspectionSnapshot,
  CurrentAccountSecuritySnapshot,
  VerificationResendWindow,
  VerificationStatusView,
} from './views.js'
import type { AuditEvent, AuditEventPage, AuditEventQuery } from './audit.js'
import type {
  AuthResult,
  AssertCurrentAccountReAuthInput,
  CancelCurrentAccountContactChangeInput,
  GetCurrentAccountClosureExportSnapshotInput,
  GetCurrentAccountSecuritySnapshotInput,
  GetCurrentAccountReAuthStatusInput,
  GetCurrentAccountAuditEventPageInput,
  GetCurrentAccountInspectionSnapshotInput,
  ConsumeVerificationInput,
  CancelOtpChallengeInput,
  CancelVerificationInput,
  CreateSessionInput,
  CreateSessionResult,
  CreateVerificationInput,
  CreateVerificationResult,
  FinishCurrentAccountContactChangeInput,
  FinishCurrentAccountOtpReAuthInput,
  FinishOtpChallengeInput,
  FinishOtpSignInInput,
  GetAccountInspectionSnapshotInput,
  LinkCurrentIdentityByTokenInput,
  CurrentAccountOtpReAuthConfirmation,
  CurrentAccountReAuthAssertion,
  CurrentAccountReAuthStatus,
  StartCurrentAccountOtpReAuthInput,
  ResendCurrentAccountOtpReAuthInput,
  CancelCurrentAccountOtpReAuthInput,
  CloseCurrentAccountByTokenInput,
  CloseCurrentAccountByTokenResult,
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
  ResendCurrentAccountContactChangeInput,
  ResendOtpChallengeInput,
  ResolveSessionContextInput,
  ResolveSessionInput,
  ResolvedSessionContext,
  SignInInput,
  StartCurrentAccountContactChangeInput,
  StartOtpChallengeInput,
  StartOtpChallengeResult,
  TouchSessionInput,
  UnlinkInput,
  UnlinkCurrentIdentityByTokenInput,
  UpdateCurrentAccountProfileByTokenInput,
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

export interface PublicAuthResult {
  readonly user: AccountSecurityUserView
  readonly identity: AccountSecurityIdentityView
  readonly session: AccountSecuritySessionView
  readonly sessionToken: string
  readonly isNewUser: boolean
  readonly isNewIdentity: boolean
}

export interface AccountLinkResult {
  readonly user: AccountSecurityUserView
  readonly identity: AccountSecurityIdentityView
  readonly linked: boolean
}

export interface AccountClosureResult {
  readonly user: AccountSecurityUserView
  readonly currentSessionId: SessionId
  readonly revokedSessionIds: readonly SessionId[]
}

export interface AccountAuditEventPage {
  readonly events: readonly AuditEventView[]
  readonly nextCursor?: AuditEventPage['nextCursor']
}

export interface AuthPublicFacade {
  readonly provider: {
    signIn(input: SignInInput): Promise<PublicAuthResult>
  }
  readonly otp: {
    start(input: StartOtpChallengeInput): Promise<StartOtpChallengeResult>
    resend(input: ResendOtpChallengeInput): Promise<StartOtpChallengeResult>
    signIn(input: FinishOtpSignInInput): Promise<PublicAuthResult>
  }
  readonly magicLink: {
    start(input: StartEmailMagicLinkSignInInput): Promise<StartEmailMagicLinkSignInResult>
    resend(input: ResendEmailMagicLinkSignInInput): Promise<StartEmailMagicLinkSignInResult>
    finish(input: FinishEmailMagicLinkSignInInput): Promise<PublicAuthResult>
  }
  readonly password: {
    signIn(input: SignInWithPasswordInput): Promise<PublicAuthResult>
  }
  readonly passwordRecovery: {
    start(input: StartEmailPasswordRecoveryInput): Promise<StartEmailPasswordRecoveryResult>
    resend(input: ResendEmailPasswordRecoveryInput): Promise<StartEmailPasswordRecoveryResult>
  }
}

export interface AuthAccountFacade {
  readonly profile: {
    update(input: UpdateCurrentAccountProfileByTokenInput): Promise<AccountSecurityUserView>
  }
  readonly contact: {
    start(input: StartCurrentAccountContactChangeInput): Promise<StartOtpChallengeResult>
    resend(input: ResendCurrentAccountContactChangeInput): Promise<StartOtpChallengeResult>
    cancel(input: CancelCurrentAccountContactChangeInput): Promise<VerificationStatusView>
    finish(input: FinishCurrentAccountContactChangeInput): Promise<AccountSecurityUserView>
  }
  readonly password: {
    set(input: SetCurrentAccountPasswordByTokenInput): Promise<AccountSecurityCredentialView>
    confirm(
      input: ConfirmCurrentAccountPasswordByTokenInput,
    ): Promise<CurrentAccountPasswordReAuthConfirmation>
    change(input: ChangeCurrentAccountPasswordByTokenInput): Promise<AccountSecurityCredentialView>
  }
  readonly reAuth: {
    status(input: GetCurrentAccountReAuthStatusInput): Promise<CurrentAccountReAuthStatus>
    assert(input: AssertCurrentAccountReAuthInput): Promise<CurrentAccountReAuthAssertion>
    startOtp(input: StartCurrentAccountOtpReAuthInput): Promise<StartOtpChallengeResult>
    resendOtp(input: ResendCurrentAccountOtpReAuthInput): Promise<StartOtpChallengeResult>
    cancelOtp(input: CancelCurrentAccountOtpReAuthInput): Promise<VerificationStatusView>
    finishOtp(
      input: FinishCurrentAccountOtpReAuthInput,
    ): Promise<CurrentAccountOtpReAuthConfirmation>
    confirmPassword(
      input: ConfirmCurrentAccountPasswordByTokenInput,
    ): Promise<CurrentAccountPasswordReAuthConfirmation>
  }
  readonly sessions: {
    revokeCurrent(input: RevokeCurrentSessionByTokenInput): Promise<void>
    revokeOwned(input: RevokeOwnedSessionByTokenInput): Promise<RevokeOwnedSessionByTokenResult>
    revokeOther(input: RevokeOtherSessionsByTokenInput): Promise<RevokeOtherSessionsByTokenResult>
  }
  readonly identities: {
    link(input: LinkCurrentIdentityByTokenInput): Promise<AccountLinkResult>
    unlink(input: UnlinkCurrentIdentityByTokenInput): Promise<void>
  }
  readonly security: {
    snapshot(input: GetCurrentAccountSecuritySnapshotInput): Promise<CurrentAccountSecuritySnapshot>
  }
  readonly inspection: {
    snapshot(
      input: GetCurrentAccountInspectionSnapshotInput,
    ): Promise<CurrentAccountInspectionSnapshot>
    closureExport(
      input: GetCurrentAccountClosureExportSnapshotInput,
    ): Promise<CurrentAccountClosureExportSnapshot>
    auditPage(input: GetCurrentAccountAuditEventPageInput): Promise<AccountAuditEventPage>
  }
  readonly closure: {
    close(input: CloseCurrentAccountByTokenInput): Promise<AccountClosureResult>
  }
}

export interface AuthAdminFacade {
  readonly users: {
    get(userId: UserId): Promise<User>
    identities(userId: UserId): Promise<readonly AuthIdentity[]>
    credentials(userId: UserId): Promise<readonly Credential[]>
    sessions(userId: UserId): Promise<readonly Session[]>
    revokeSessions(input: RevokeUserSessionsInput): Promise<RevokeUserSessionsResult>
    securitySnapshot(userId: UserId): Promise<AccountSecuritySnapshot>
    inspectionSnapshot(input: GetAccountInspectionSnapshotInput): Promise<AccountInspectionSnapshot>
  }
  readonly accounts: {
    link(input: LinkInput): Promise<LinkResult>
    unlink(input: UnlinkInput): Promise<void>
    merge(input: MergeAccountsInput): Promise<MergeResult>
  }
  readonly sessions: {
    create(input: CreateSessionInput): Promise<CreateSessionResult>
    revoke(sessionId: SessionId): Promise<void>
    touch(input: TouchSessionInput): Promise<Session>
    resolve(input: ResolveSessionInput): Promise<Session>
    context(input: ResolveSessionContextInput): Promise<ResolvedSessionContext>
  }
  readonly verifications: {
    create(input: CreateVerificationInput): Promise<CreateVerificationResult>
    get(verificationId: VerificationId): Promise<Verification>
    cancel(input: CancelVerificationInput): Promise<Verification>
    consume(input: ConsumeVerificationInput): Promise<Verification>
    finishOtp(input: FinishOtpChallengeInput): Promise<Verification>
    cancelOtp(input: CancelOtpChallengeInput): Promise<Verification>
    cancelMagicLink(input: CancelEmailMagicLinkSignInInput): Promise<Verification>
    cancelPasswordRecovery(input: CancelEmailPasswordRecoveryInput): Promise<Verification>
    resendWindow(input: GetVerificationResendWindowInput): Promise<VerificationResendWindow>
  }
  readonly credentials: {
    setPassword(input: SetPasswordInput): Promise<Credential>
    changePassword(input: ChangePasswordInput): Promise<Credential>
    finishPasswordRecovery(input: FinishEmailPasswordRecoveryInput): Promise<Credential>
  }
  readonly audit: {
    events(input?: AuditEventQuery): Promise<readonly AuditEvent[]>
    page(input?: AuditEventQuery): Promise<AuditEventPage>
  }
}

export interface AuthService {
  readonly public: AuthPublicFacade
  readonly account: AuthAccountFacade
  readonly admin: AuthAdminFacade

  signIn(input: SignInInput): Promise<AuthResult>
  signInWithPassword(input: SignInWithPasswordInput): Promise<AuthResult>
  startOtpChallenge(input: StartOtpChallengeInput): Promise<StartOtpChallengeResult>
  startCurrentAccountOtpReAuth(
    input: StartCurrentAccountOtpReAuthInput,
  ): Promise<StartOtpChallengeResult>
  resendCurrentAccountOtpReAuth(
    input: ResendCurrentAccountOtpReAuthInput,
  ): Promise<StartOtpChallengeResult>
  cancelCurrentAccountOtpReAuth(input: CancelCurrentAccountOtpReAuthInput): Promise<Verification>
  finishCurrentAccountOtpReAuth(
    input: FinishCurrentAccountOtpReAuthInput,
  ): Promise<CurrentAccountOtpReAuthConfirmation>
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
  getCurrentAccountReAuthStatus(
    input: GetCurrentAccountReAuthStatusInput,
  ): Promise<CurrentAccountReAuthStatus>
  assertCurrentAccountReAuth(
    input: AssertCurrentAccountReAuthInput,
  ): Promise<CurrentAccountReAuthAssertion>
  getCurrentAccountSecuritySnapshot(
    input: GetCurrentAccountSecuritySnapshotInput,
  ): Promise<CurrentAccountSecuritySnapshot>
  getCurrentAccountInspectionSnapshot(
    input: GetCurrentAccountInspectionSnapshotInput,
  ): Promise<CurrentAccountInspectionSnapshot>
  getCurrentAccountClosureExportSnapshot(
    input: GetCurrentAccountClosureExportSnapshotInput,
  ): Promise<CurrentAccountClosureExportSnapshot>
  getCurrentAccountAuditEventPage(
    input: GetCurrentAccountAuditEventPageInput,
  ): Promise<AuditEventPage>
  linkCurrentIdentityByToken(input: LinkCurrentIdentityByTokenInput): Promise<LinkResult>
  revokeCurrentSessionByToken(input: RevokeCurrentSessionByTokenInput): Promise<void>
  revokeOwnedSessionByToken(
    input: RevokeOwnedSessionByTokenInput,
  ): Promise<RevokeOwnedSessionByTokenResult>
  revokeOtherSessionsByToken(
    input: RevokeOtherSessionsByTokenInput,
  ): Promise<RevokeOtherSessionsByTokenResult>
  unlinkCurrentIdentityByToken(input: UnlinkCurrentIdentityByTokenInput): Promise<void>
  closeCurrentAccountByToken(
    input: CloseCurrentAccountByTokenInput,
  ): Promise<CloseCurrentAccountByTokenResult>
  updateCurrentAccountProfileByToken(input: UpdateCurrentAccountProfileByTokenInput): Promise<User>
  startCurrentAccountContactChange(
    input: StartCurrentAccountContactChangeInput,
  ): Promise<StartOtpChallengeResult>
  resendCurrentAccountContactChange(
    input: ResendCurrentAccountContactChangeInput,
  ): Promise<StartOtpChallengeResult>
  cancelCurrentAccountContactChange(
    input: CancelCurrentAccountContactChangeInput,
  ): Promise<Verification>
  finishCurrentAccountContactChange(input: FinishCurrentAccountContactChangeInput): Promise<User>
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
