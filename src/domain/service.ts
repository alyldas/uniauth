import type { AuthIdentity, Credential, Session, Verification } from './entities.js'
import type {
  AuthResult,
  ConsumeVerificationInput,
  CreateSessionInput,
  CreateSessionResult,
  CreateVerificationInput,
  CreateVerificationResult,
  FinishOtpChallengeInput,
  FinishOtpSignInInput,
  LinkInput,
  LinkResult,
  MergeAccountsInput,
  MergeResult,
  ResolveSessionInput,
  SignInInput,
  StartOtpChallengeInput,
  StartOtpChallengeResult,
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
  resolveSession(input: ResolveSessionInput): Promise<Session>
  getUserIdentities(userId: UserId): Promise<readonly AuthIdentity[]>
  createSession(input: CreateSessionInput): Promise<CreateSessionResult>
  createVerification(input: CreateVerificationInput): Promise<CreateVerificationResult>
  consumeVerification(input: ConsumeVerificationInput): Promise<Verification>
}
