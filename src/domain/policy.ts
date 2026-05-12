export const AuthPolicyAction = {
  SignIn: 'signIn',
  Link: 'link',
  Unlink: 'unlink',
  MergeAccounts: 'mergeAccounts',
  SetPassword: 'setPassword',
  ChangePassword: 'changePassword',
  UpdateProfile: 'updateProfile',
  UpdateContact: 'updateContact',
  CloseAccount: 'closeAccount',
} as const

export type AuthPolicyAction = (typeof AuthPolicyAction)[keyof typeof AuthPolicyAction]
