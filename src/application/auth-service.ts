import { getAccountInspectionSnapshot } from './account-inspection.js'
import { getAccountSecuritySnapshot } from './account-security.js'
import { getAuditEventPage, getAuditEvents } from './audit-events.js'
import { getUserIdentities, link, mergeAccounts, unlink } from './accounts.js'
import { getUserCredentials } from './credentials.js'
import {
  getCurrentAccountAuditEventPage,
  getCurrentAccountClosureExportSnapshot,
  getCurrentAccountInspectionSnapshot,
} from './current-account-inspection.js'
import {
  getCurrentAccountSecuritySnapshot,
  revokeCurrentSessionByToken,
  revokeOtherSessionsByToken,
} from './current-account-security.js'
import {
  changeCurrentAccountPasswordByToken,
  closeCurrentAccountByToken,
  linkCurrentIdentityByToken,
  revokeOwnedSessionByToken,
  setCurrentAccountPasswordByToken,
  unlinkCurrentIdentityByToken,
  updateCurrentAccountProfileByToken,
} from './current-account-actions.js'
import {
  cancelCurrentAccountContactChange,
  finishCurrentAccountContactChange,
  resendCurrentAccountContactChange,
  startCurrentAccountContactChange,
} from './current-account-contact-change.js'
import {
  assertCurrentAccountReAuth,
  cancelCurrentAccountOtpReAuth,
  finishCurrentAccountOtpReAuth,
  getCurrentAccountReAuthStatus,
  confirmCurrentAccountPasswordByToken,
  resendCurrentAccountOtpReAuth,
  startCurrentAccountOtpReAuth,
} from './current-account-re-auth.js'
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
import { createAuthServiceRuntime, type DefaultAuthServiceOptions } from './runtime-defaults.js'
import type { AuthServiceRuntime } from './runtime.js'
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
import {
  toAccountSecurityCredentialView,
  toAccountSecurityIdentityView,
  toAccountSecuritySessionView,
  toAccountSecurityUserView,
  toAuditEventView,
  toVerificationStatusView,
} from '../domain/types.js'
import type {
  AuthIdentity,
  AccountAuditEventPage,
  AccountClosureResult,
  AccountInspectionSnapshot,
  AccountLinkResult,
  AccountSecurityCredentialView,
  AccountSecuritySnapshot,
  AccountSecurityUserView,
  AuditEvent,
  AuditEventPage,
  AuditEventQuery,
  AssertCurrentAccountReAuthInput,
  AuthResult,
  AuthAccountFacade,
  AuthAdminFacade,
  AuthService,
  AuthPublicFacade,
  PublicAuthResult,
  CancelCurrentAccountContactChangeInput,
  CurrentAccountClosureExportSnapshot,
  CurrentAccountInspectionSnapshot,
  CurrentAccountOtpReAuthConfirmation,
  CurrentAccountReAuthAssertion,
  CurrentAccountReAuthStatus,
  CurrentAccountSecuritySnapshot,
  CancelEmailMagicLinkSignInInput,
  CancelEmailPasswordRecoveryInput,
  CancelOtpChallengeInput,
  CancelVerificationInput,
  ChangePasswordInput,
  ChangeCurrentAccountPasswordByTokenInput,
  ConfirmCurrentAccountPasswordByTokenInput,
  Credential,
  CurrentAccountPasswordReAuthConfirmation,
  ConsumeVerificationInput,
  CreateSessionInput,
  CreateSessionResult,
  CreateVerificationInput,
  CreateVerificationResult,
  FinishCurrentAccountContactChangeInput,
  FinishCurrentAccountOtpReAuthInput,
  FinishEmailMagicLinkSignInInput,
  FinishEmailPasswordRecoveryInput,
  FinishOtpChallengeInput,
  FinishOtpSignInInput,
  GetAccountInspectionSnapshotInput,
  CancelCurrentAccountOtpReAuthInput,
  CloseCurrentAccountByTokenInput,
  CloseCurrentAccountByTokenResult,
  GetCurrentAccountAuditEventPageInput,
  GetCurrentAccountClosureExportSnapshotInput,
  GetCurrentAccountInspectionSnapshotInput,
  GetCurrentAccountReAuthStatusInput,
  GetCurrentAccountSecuritySnapshotInput,
  GetVerificationResendWindowInput,
  LinkCurrentIdentityByTokenInput,
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
  ResendCurrentAccountOtpReAuthInput,
  ResendOtpChallengeInput,
  ResolveSessionContextInput,
  ResolveSessionInput,
  ResolvedSessionContext,
  Session,
  SessionId,
  SetPasswordInput,
  SetCurrentAccountPasswordByTokenInput,
  SignInInput,
  SignInWithPasswordInput,
  StartCurrentAccountContactChangeInput,
  StartCurrentAccountOtpReAuthInput,
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
  UnlinkCurrentIdentityByTokenInput,
  UpdateCurrentAccountProfileByTokenInput,
  User,
  UserId,
  Verification,
  VerificationResendWindow,
  VerificationId,
  VerificationStatusView,
} from '../domain/types.js'
export type { DefaultAuthServiceOptions } from './runtime-defaults.js'

export class DefaultAuthService implements AuthService {
  readonly public: AuthPublicFacade
  readonly account: AuthAccountFacade
  readonly admin: AuthAdminFacade

  private readonly runtime: AuthServiceRuntime

  constructor(options: DefaultAuthServiceOptions) {
    this.runtime = createAuthServiceRuntime(options)
    this.public = {
      provider: {
        signIn: this.publicSignIn.bind(this),
      },
      otp: {
        start: this.startOtpChallenge.bind(this),
        resend: this.resendOtpChallenge.bind(this),
        signIn: this.publicFinishOtpSignIn.bind(this),
      },
      magicLink: {
        start: this.startEmailMagicLinkSignIn.bind(this),
        resend: this.resendEmailMagicLinkSignIn.bind(this),
        finish: this.publicFinishEmailMagicLinkSignIn.bind(this),
      },
      password: {
        signIn: this.publicSignInWithPassword.bind(this),
      },
      passwordRecovery: {
        start: this.startEmailPasswordRecovery.bind(this),
        resend: this.resendEmailPasswordRecovery.bind(this),
      },
    }
    this.account = {
      profile: {
        update: this.accountUpdateProfile.bind(this),
      },
      contact: {
        start: this.startCurrentAccountContactChange.bind(this),
        resend: this.resendCurrentAccountContactChange.bind(this),
        cancel: this.accountCancelContactChange.bind(this),
        finish: this.accountFinishContactChange.bind(this),
      },
      password: {
        set: this.accountSetPassword.bind(this),
        confirm: this.confirmCurrentAccountPasswordByToken.bind(this),
        change: this.accountChangePassword.bind(this),
      },
      reAuth: {
        status: this.getCurrentAccountReAuthStatus.bind(this),
        assert: this.assertCurrentAccountReAuth.bind(this),
        startOtp: this.startCurrentAccountOtpReAuth.bind(this),
        resendOtp: this.resendCurrentAccountOtpReAuth.bind(this),
        cancelOtp: this.accountCancelOtpReAuth.bind(this),
        finishOtp: this.finishCurrentAccountOtpReAuth.bind(this),
        confirmPassword: this.confirmCurrentAccountPasswordByToken.bind(this),
      },
      sessions: {
        revokeCurrent: this.revokeCurrentSessionByToken.bind(this),
        revokeOwned: this.revokeOwnedSessionByToken.bind(this),
        revokeOther: this.revokeOtherSessionsByToken.bind(this),
      },
      identities: {
        link: this.accountLinkIdentity.bind(this),
        unlink: this.unlinkCurrentIdentityByToken.bind(this),
      },
      security: {
        snapshot: this.getCurrentAccountSecuritySnapshot.bind(this),
      },
      inspection: {
        snapshot: this.getCurrentAccountInspectionSnapshot.bind(this),
        closureExport: this.getCurrentAccountClosureExportSnapshot.bind(this),
        auditPage: this.accountAuditEventPage.bind(this),
      },
      closure: {
        close: this.accountClose.bind(this),
      },
    }
    this.admin = {
      users: {
        get: this.getUser.bind(this),
        identities: this.getUserIdentities.bind(this),
        credentials: this.getUserCredentials.bind(this),
        sessions: this.getUserSessions.bind(this),
        revokeSessions: this.revokeUserSessions.bind(this),
        securitySnapshot: this.getAccountSecuritySnapshot.bind(this),
        inspectionSnapshot: this.getAccountInspectionSnapshot.bind(this),
      },
      accounts: {
        link: this.link.bind(this),
        unlink: this.unlink.bind(this),
        merge: this.mergeAccounts.bind(this),
      },
      sessions: {
        create: this.createSession.bind(this),
        revoke: this.revokeSession.bind(this),
        touch: this.touchSession.bind(this),
        resolve: this.resolveSession.bind(this),
        context: this.resolveSessionContext.bind(this),
      },
      verifications: {
        create: this.createVerification.bind(this),
        get: this.getVerification.bind(this),
        cancel: this.cancelVerification.bind(this),
        consume: this.consumeVerification.bind(this),
        finishOtp: this.finishOtpChallenge.bind(this),
        cancelOtp: this.cancelOtpChallenge.bind(this),
        cancelMagicLink: this.cancelEmailMagicLinkSignIn.bind(this),
        cancelPasswordRecovery: this.cancelEmailPasswordRecovery.bind(this),
        resendWindow: this.getVerificationResendWindow.bind(this),
      },
      credentials: {
        setPassword: this.setPassword.bind(this),
        changePassword: this.changePassword.bind(this),
        finishPasswordRecovery: this.finishEmailPasswordRecovery.bind(this),
      },
      audit: {
        events: this.getAuditEvents.bind(this),
        page: this.getAuditEventPage.bind(this),
      },
    }
  }

  async signIn(input: SignInInput): Promise<AuthResult> {
    return signIn(this.runtime, input)
  }

  private async publicSignIn(input: SignInInput): Promise<PublicAuthResult> {
    return toPublicAuthResult(await this.signIn(input))
  }

  async signInWithPassword(input: SignInWithPasswordInput): Promise<AuthResult> {
    return signInWithPassword(this.runtime, input)
  }

  private async publicSignInWithPassword(
    input: SignInWithPasswordInput,
  ): Promise<PublicAuthResult> {
    return toPublicAuthResult(await this.signInWithPassword(input))
  }

  async startOtpChallenge(input: StartOtpChallengeInput): Promise<StartOtpChallengeResult> {
    return startOtpChallenge(this.runtime, input)
  }

  async startCurrentAccountOtpReAuth(
    input: StartCurrentAccountOtpReAuthInput,
  ): Promise<StartOtpChallengeResult> {
    return startCurrentAccountOtpReAuth(this.runtime, input)
  }

  async resendCurrentAccountOtpReAuth(
    input: ResendCurrentAccountOtpReAuthInput,
  ): Promise<StartOtpChallengeResult> {
    return resendCurrentAccountOtpReAuth(this.runtime, input)
  }

  async cancelCurrentAccountOtpReAuth(
    input: CancelCurrentAccountOtpReAuthInput,
  ): Promise<Verification> {
    return cancelCurrentAccountOtpReAuth(this.runtime, input)
  }

  private async accountCancelOtpReAuth(
    input: CancelCurrentAccountOtpReAuthInput,
  ): Promise<VerificationStatusView> {
    return toVerificationStatusView(await this.cancelCurrentAccountOtpReAuth(input))
  }

  async finishCurrentAccountOtpReAuth(
    input: FinishCurrentAccountOtpReAuthInput,
  ): Promise<CurrentAccountOtpReAuthConfirmation> {
    return finishCurrentAccountOtpReAuth(this.runtime, input)
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

  private async publicFinishOtpSignIn(input: FinishOtpSignInInput): Promise<PublicAuthResult> {
    return toPublicAuthResult(await this.finishOtpSignIn(input))
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

  private async publicFinishEmailMagicLinkSignIn(
    input: FinishEmailMagicLinkSignInInput,
  ): Promise<PublicAuthResult> {
    return toPublicAuthResult(await this.finishEmailMagicLinkSignIn(input))
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

  async getCurrentAccountReAuthStatus(
    input: GetCurrentAccountReAuthStatusInput,
  ): Promise<CurrentAccountReAuthStatus> {
    return getCurrentAccountReAuthStatus(this.runtime, input)
  }

  async assertCurrentAccountReAuth(
    input: AssertCurrentAccountReAuthInput,
  ): Promise<CurrentAccountReAuthAssertion> {
    return assertCurrentAccountReAuth(this.runtime, input)
  }

  async getCurrentAccountSecuritySnapshot(
    input: GetCurrentAccountSecuritySnapshotInput,
  ): Promise<CurrentAccountSecuritySnapshot> {
    return getCurrentAccountSecuritySnapshot(this.runtime, input)
  }

  async getCurrentAccountInspectionSnapshot(
    input: GetCurrentAccountInspectionSnapshotInput,
  ): Promise<CurrentAccountInspectionSnapshot> {
    return getCurrentAccountInspectionSnapshot(this.runtime, input)
  }

  async getCurrentAccountClosureExportSnapshot(
    input: GetCurrentAccountClosureExportSnapshotInput,
  ): Promise<CurrentAccountClosureExportSnapshot> {
    return getCurrentAccountClosureExportSnapshot(this.runtime, input)
  }

  async getCurrentAccountAuditEventPage(
    input: GetCurrentAccountAuditEventPageInput,
  ): Promise<AuditEventPage> {
    return getCurrentAccountAuditEventPage(this.runtime, input)
  }

  private async accountAuditEventPage(
    input: GetCurrentAccountAuditEventPageInput,
  ): Promise<AccountAuditEventPage> {
    return toAccountAuditEventPage(await this.getCurrentAccountAuditEventPage(input))
  }

  async linkCurrentIdentityByToken(input: LinkCurrentIdentityByTokenInput): Promise<LinkResult> {
    return linkCurrentIdentityByToken(this.runtime, input)
  }

  private async accountLinkIdentity(
    input: LinkCurrentIdentityByTokenInput,
  ): Promise<AccountLinkResult> {
    return toAccountLinkResult(await this.linkCurrentIdentityByToken(input))
  }

  async revokeCurrentSessionByToken(input: RevokeCurrentSessionByTokenInput): Promise<void> {
    return revokeCurrentSessionByToken(this.runtime, input)
  }

  async revokeOwnedSessionByToken(
    input: RevokeOwnedSessionByTokenInput,
  ): Promise<RevokeOwnedSessionByTokenResult> {
    return revokeOwnedSessionByToken(this.runtime, input)
  }

  async revokeOtherSessionsByToken(
    input: RevokeOtherSessionsByTokenInput,
  ): Promise<RevokeOtherSessionsByTokenResult> {
    return revokeOtherSessionsByToken(this.runtime, input)
  }

  async unlinkCurrentIdentityByToken(input: UnlinkCurrentIdentityByTokenInput): Promise<void> {
    return unlinkCurrentIdentityByToken(this.runtime, input)
  }

  async closeCurrentAccountByToken(
    input: CloseCurrentAccountByTokenInput,
  ): Promise<CloseCurrentAccountByTokenResult> {
    return closeCurrentAccountByToken(this.runtime, input)
  }

  private async accountClose(
    input: CloseCurrentAccountByTokenInput,
  ): Promise<AccountClosureResult> {
    return toAccountClosureResult(await this.closeCurrentAccountByToken(input))
  }

  async updateCurrentAccountProfileByToken(
    input: UpdateCurrentAccountProfileByTokenInput,
  ): Promise<User> {
    return updateCurrentAccountProfileByToken(this.runtime, input)
  }

  private async accountUpdateProfile(
    input: UpdateCurrentAccountProfileByTokenInput,
  ): Promise<AccountSecurityUserView> {
    return toAccountSecurityUserView(await this.updateCurrentAccountProfileByToken(input))
  }

  async startCurrentAccountContactChange(
    input: StartCurrentAccountContactChangeInput,
  ): Promise<StartOtpChallengeResult> {
    return startCurrentAccountContactChange(this.runtime, input)
  }

  async resendCurrentAccountContactChange(
    input: ResendCurrentAccountContactChangeInput,
  ): Promise<StartOtpChallengeResult> {
    return resendCurrentAccountContactChange(this.runtime, input)
  }

  async cancelCurrentAccountContactChange(
    input: CancelCurrentAccountContactChangeInput,
  ): Promise<Verification> {
    return cancelCurrentAccountContactChange(this.runtime, input)
  }

  private async accountCancelContactChange(
    input: CancelCurrentAccountContactChangeInput,
  ): Promise<VerificationStatusView> {
    return toVerificationStatusView(await this.cancelCurrentAccountContactChange(input))
  }

  async finishCurrentAccountContactChange(
    input: FinishCurrentAccountContactChangeInput,
  ): Promise<User> {
    return finishCurrentAccountContactChange(this.runtime, input)
  }

  private async accountFinishContactChange(
    input: FinishCurrentAccountContactChangeInput,
  ): Promise<AccountSecurityUserView> {
    return toAccountSecurityUserView(await this.finishCurrentAccountContactChange(input))
  }

  async setCurrentAccountPasswordByToken(
    input: SetCurrentAccountPasswordByTokenInput,
  ): Promise<Credential> {
    return setCurrentAccountPasswordByToken(this.runtime, input)
  }

  private async accountSetPassword(
    input: SetCurrentAccountPasswordByTokenInput,
  ): Promise<AccountSecurityCredentialView> {
    return toAccountSecurityCredentialView(await this.setCurrentAccountPasswordByToken(input))
  }

  async confirmCurrentAccountPasswordByToken(
    input: ConfirmCurrentAccountPasswordByTokenInput,
  ): Promise<CurrentAccountPasswordReAuthConfirmation> {
    return confirmCurrentAccountPasswordByToken(this.runtime, input)
  }

  async changeCurrentAccountPasswordByToken(
    input: ChangeCurrentAccountPasswordByTokenInput,
  ): Promise<Credential> {
    return changeCurrentAccountPasswordByToken(this.runtime, input)
  }

  private async accountChangePassword(
    input: ChangeCurrentAccountPasswordByTokenInput,
  ): Promise<AccountSecurityCredentialView> {
    return toAccountSecurityCredentialView(await this.changeCurrentAccountPasswordByToken(input))
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

function toPublicAuthResult(result: AuthResult): PublicAuthResult {
  return {
    user: toAccountSecurityUserView(result.user),
    identity: toAccountSecurityIdentityView(result.identity),
    session: toAccountSecuritySessionView(result.session),
    sessionToken: result.sessionToken,
    isNewUser: result.isNewUser,
    isNewIdentity: result.isNewIdentity,
  }
}

function toAccountLinkResult(result: LinkResult): AccountLinkResult {
  return {
    user: toAccountSecurityUserView(result.user),
    identity: toAccountSecurityIdentityView(result.identity),
    linked: result.linked,
  }
}

function toAccountClosureResult(result: CloseCurrentAccountByTokenResult): AccountClosureResult {
  return {
    user: toAccountSecurityUserView(result.user),
    currentSessionId: result.currentSessionId,
    revokedSessionIds: result.revokedSessionIds,
  }
}

function toAccountAuditEventPage(page: AuditEventPage): AccountAuditEventPage {
  return {
    events: page.events.map((event) => toAuditEventView(event)),
    ...(page.nextCursor ? { nextCursor: page.nextCursor } : {}),
  }
}
