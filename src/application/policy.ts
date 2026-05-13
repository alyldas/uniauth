export { AuthPolicyAction } from '../domain/policy.js'
import {
  AuthPolicyAction,
  type AuthPolicyAction as AuthPolicyActionType,
} from '../domain/policy.js'
import type { AuthIdentity, ProviderIdentityAssertion, User, UserId } from '../domain/types.js'
import { invalidInput } from '../errors.js'

export type MaybePromise<T> = T | Promise<T>

export interface AutoLinkContext {
  readonly assertion: ProviderIdentityAssertion
  readonly targetUser: User
  readonly existingIdentities: readonly AuthIdentity[]
}

export interface LinkIdentityContext {
  readonly user: User
  readonly assertion: ProviderIdentityAssertion
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
  readonly sourceIdentities: readonly AuthIdentity[]
  readonly targetIdentities: readonly AuthIdentity[]
}

export interface ReAuthContext {
  readonly action: AuthPolicyActionType
  readonly userId: UserId
  readonly reAuthenticatedAt?: Date | undefined
  readonly now: Date
}

export interface AuthPolicy {
  canAutoLink(context: AutoLinkContext): MaybePromise<boolean>
  canLinkIdentity?(context: LinkIdentityContext): MaybePromise<boolean>
  canUnlinkIdentity(context: UnlinkIdentityContext): MaybePromise<boolean>
  canMergeUsers(context: MergeUsersContext): MaybePromise<boolean>
  requiresReAuth(context: ReAuthContext): MaybePromise<boolean>
}

export interface DefaultAuthPolicyOptions {
  readonly allowAutoLink?: boolean
  readonly allowMergeAccounts?: boolean
  readonly requireReAuthFor?: readonly AuthPolicyActionType[]
  readonly reAuthMaxAgeSeconds?: number
}

export function createDefaultAuthPolicy(options: DefaultAuthPolicyOptions = {}): AuthPolicy {
  if (!isPolicyOptions(options)) {
    throw invalidInput('Default auth policy options must be a plain object.')
  }

  if (
    options.requireReAuthFor !== undefined &&
    (!Array.isArray(options.requireReAuthFor) ||
      options.requireReAuthFor.some((action) => typeof action !== 'string' || !action.trim()))
  ) {
    throw invalidInput('Default auth policy re-auth actions must be non-blank strings.')
  }

  const reAuthMaxAgeSeconds = options.reAuthMaxAgeSeconds ?? 15 * 60

  if (!Number.isFinite(reAuthMaxAgeSeconds) || reAuthMaxAgeSeconds < 0) {
    throw invalidInput('Default auth policy re-auth max age must be a non-negative number.')
  }

  const requireReAuthFor = new Set<AuthPolicyActionType>(
    options.requireReAuthFor ?? [AuthPolicyAction.MergeAccounts, AuthPolicyAction.CloseAccount],
  )
  const reAuthMaxAgeMs = reAuthMaxAgeSeconds * 1000

  return {
    canAutoLink(): boolean {
      return options.allowAutoLink === true
    },
    canLinkIdentity(): boolean {
      return true
    },
    canUnlinkIdentity(context): boolean {
      return context.activeIdentityCount > 1
    },
    canMergeUsers(): boolean {
      return options.allowMergeAccounts === true
    },
    requiresReAuth(context): boolean {
      if (!isRecord(context)) {
        throw invalidInput('Default auth policy re-auth context is required.')
      }

      if (!requireReAuthFor.has(context.action)) {
        return false
      }

      if (!(context.now instanceof Date) || Number.isNaN(context.now.getTime())) {
        throw invalidInput('Default auth policy re-auth time is invalid.')
      }

      if (!context.reAuthenticatedAt) {
        return true
      }

      if (
        !(context.reAuthenticatedAt instanceof Date) ||
        Number.isNaN(context.reAuthenticatedAt.getTime())
      ) {
        throw invalidInput('Default auth policy re-auth timestamp is invalid.')
      }

      return context.now.getTime() - context.reAuthenticatedAt.getTime() > reAuthMaxAgeMs
    },
  }
}

export const defaultAuthPolicy: AuthPolicy = createDefaultAuthPolicy()

function isPolicyOptions(value: unknown): value is DefaultAuthPolicyOptions {
  if (!isRecord(value)) {
    return false
  }

  const prototype = Object.getPrototypeOf(value)
  return prototype === Object.prototype || prototype === null
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}
