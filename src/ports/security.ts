import type { UserId } from '../domain/types.js'

export interface PasswordHasher {
  hash(password: string): Promise<string>
  verify(password: string, passwordHash: string): Promise<boolean>
}

export const PasswordPolicyPurpose = {
  SetPassword: 'set_password',
  ChangePassword: 'change_password',
  PasswordRecovery: 'password_recovery',
} as const

export type PasswordPolicyPurpose =
  (typeof PasswordPolicyPurpose)[keyof typeof PasswordPolicyPurpose]

export interface PasswordPolicyInput {
  readonly password: string
  readonly purpose: PasswordPolicyPurpose
  readonly userId?: UserId
  readonly email?: string
  readonly now: Date
}

export interface PasswordPolicyDecision {
  readonly allowed: boolean
  readonly reason?: string
}

export interface PasswordPolicy {
  validate(
    input: PasswordPolicyInput,
  ): PasswordPolicyDecision | void | Promise<PasswordPolicyDecision | void>
}
