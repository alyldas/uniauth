import { getUserIdentities, link, mergeAccounts, unlink } from './accounts.js'
import {
  finishEmailOtpSignIn,
  finishOtpChallenge,
  finishOtpSignIn,
  startEmailOtpSignIn,
  startOtpChallenge,
} from './otp.js'
import { type AuthServiceRuntime, createAuthServiceRuntime } from './runtime.js'
import { createSession, revokeSession } from './sessions.js'
import { signIn } from './sign-in.js'
import { consumeVerification, createVerification } from './verifications.js'
import type { AuthPolicy } from './policy.js'
import type {
  AuthIdentity,
  AuthResult,
  AuthService,
  Clock,
  ConsumeVerificationInput,
  CreateSessionInput,
  CreateVerificationInput,
  CreateVerificationResult,
  FinishEmailOtpSignInInput,
  FinishOtpChallengeInput,
  FinishOtpSignInInput,
  IdGenerator,
  LinkInput,
  LinkResult,
  MergeAccountsInput,
  MergeResult,
  Session,
  SessionId,
  SignInInput,
  StartEmailOtpSignInInput,
  StartEmailOtpSignInResult,
  StartOtpChallengeInput,
  StartOtpChallengeResult,
  UnlinkInput,
  UserId,
  Verification,
} from '../domain/types.js'
import type {
  AuthServiceInfrastructure,
  AuthServiceRepositories,
  ProviderRegistry,
  UnitOfWork,
} from '../ports.js'

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
  private readonly runtime: AuthServiceRuntime

  constructor(options: DefaultAuthServiceOptions) {
    this.runtime = createAuthServiceRuntime(options)
  }

  async signIn(input: SignInInput): Promise<AuthResult> {
    return signIn(this.runtime, input)
  }

  async startOtpChallenge(input: StartOtpChallengeInput): Promise<StartOtpChallengeResult> {
    return startOtpChallenge(this.runtime, input)
  }

  async finishOtpChallenge(input: FinishOtpChallengeInput): Promise<Verification> {
    return finishOtpChallenge(this.runtime, input)
  }

  async finishOtpSignIn(input: FinishOtpSignInInput): Promise<AuthResult> {
    return finishOtpSignIn(this.runtime, input)
  }

  async startEmailOtpSignIn(input: StartEmailOtpSignInInput): Promise<StartEmailOtpSignInResult> {
    return startEmailOtpSignIn(this.runtime, input)
  }

  async finishEmailOtpSignIn(input: FinishEmailOtpSignInInput): Promise<AuthResult> {
    return finishEmailOtpSignIn(this.runtime, input)
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

  async getUserIdentities(userId: UserId): Promise<readonly AuthIdentity[]> {
    return getUserIdentities(this.runtime, userId)
  }

  async createSession(input: CreateSessionInput): Promise<Session> {
    return createSession(this.runtime, input)
  }

  async createVerification(input: CreateVerificationInput): Promise<CreateVerificationResult> {
    return createVerification(this.runtime, input)
  }

  async consumeVerification(input: ConsumeVerificationInput): Promise<Verification> {
    return consumeVerification(this.runtime, input)
  }
}

export function createAuthService(options: DefaultAuthServiceOptions): DefaultAuthService {
  return new DefaultAuthService(options)
}
