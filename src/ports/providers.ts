import type {
  AuthIdentityProvider,
  FinishInput,
  ProviderIdentityAssertion,
} from '../domain/types.js'

export interface AuthProvider {
  readonly id: AuthIdentityProvider
  finish(input: FinishInput): Promise<ProviderIdentityAssertion>
}

export interface ProviderRegistry {
  get(provider: AuthIdentityProvider): Promise<AuthProvider | undefined>
}
