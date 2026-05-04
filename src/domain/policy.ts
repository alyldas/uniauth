export const AuthPolicyAction = {
  SignIn: 'signIn',
  Link: 'link',
  Unlink: 'unlink',
  MergeAccounts: 'mergeAccounts',
  SetPassword: 'setPassword',
  ChangePassword: 'changePassword',
} as const

export type AuthPolicyAction = (typeof AuthPolicyAction)[keyof typeof AuthPolicyAction]
