import type { AuthIdentity, ProviderIdentityAssertion, User, UserId } from '../domain/types.js'

export type MaybePromise<T> = T | Promise<T>
export type AuthPolicyAction = 'signIn' | 'link' | 'unlink' | 'mergeAccounts'

export interface AutoLinkContext {
  readonly assertion: ProviderIdentityAssertion
  readonly targetUser: User
  readonly existingIdentities: readonly AuthIdentity[]
}

export interface UnlinkIdentityContext {
  readonly user: User
  readonly identity: AuthIdentity
  readonly activeIdentityCount: number
}

export interface MergeUsersContext {
  readonly sourceUser: User
  readonly targetUser: User
  readonly sourceIdentityCount: number
}

export interface ReAuthContext {
  readonly action: AuthPolicyAction
  readonly userId: UserId
  readonly reAuthenticatedAt?: Date | undefined
  readonly now: Date
}

export interface AuthPolicy {
  canAutoLink(context: AutoLinkContext): MaybePromise<boolean>
  canUnlinkIdentity(context: UnlinkIdentityContext): MaybePromise<boolean>
  canMergeUsers(context: MergeUsersContext): MaybePromise<boolean>
  requiresReAuth(context: ReAuthContext): MaybePromise<boolean>
}

export interface DefaultAuthPolicyOptions {
  readonly allowAutoLink?: boolean
  readonly allowMergeAccounts?: boolean
  readonly requireReAuthFor?: readonly AuthPolicyAction[]
  readonly reAuthMaxAgeSeconds?: number
}

export function createDefaultAuthPolicy(options: DefaultAuthPolicyOptions = {}): AuthPolicy {
  const requireReAuthFor = new Set<AuthPolicyAction>(options.requireReAuthFor ?? ['mergeAccounts'])
  const reAuthMaxAgeMs = (options.reAuthMaxAgeSeconds ?? 15 * 60) * 1000

  return {
    canAutoLink(): boolean {
      return options.allowAutoLink === true
    },
    canUnlinkIdentity(context): boolean {
      return context.activeIdentityCount > 1
    },
    canMergeUsers(): boolean {
      return options.allowMergeAccounts === true
    },
    requiresReAuth(context): boolean {
      if (!requireReAuthFor.has(context.action)) {
        return false
      }

      if (!context.reAuthenticatedAt) {
        return true
      }

      return context.now.getTime() - context.reAuthenticatedAt.getTime() > reAuthMaxAgeMs
    },
  }
}

export const defaultAuthPolicy: AuthPolicy = createDefaultAuthPolicy()
