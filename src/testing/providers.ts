import type {
  AuthIdentityProvider,
  ProviderIdentityAssertion,
  StartResult,
} from '../domain/types.js'
import type { AuthProvider, ProviderRegistry } from '../ports'

export class StaticAuthProvider implements AuthProvider {
  readonly id: AuthIdentityProvider
  private assertion: ProviderIdentityAssertion

  constructor(id: AuthIdentityProvider, assertion: Omit<ProviderIdentityAssertion, 'provider'>) {
    this.id = id
    this.assertion = { provider: id, ...assertion }
  }

  async start(): Promise<StartResult> {
    return { kind: 'noop' }
  }

  async finish(): Promise<ProviderIdentityAssertion> {
    return this.assertion
  }

  /** Replace the next assertion returned by this test provider. */
  setAssertion(assertion: Omit<ProviderIdentityAssertion, 'provider'>): void {
    this.assertion = { provider: this.id, ...assertion }
  }
}

export class InMemoryProviderRegistry implements ProviderRegistry {
  private readonly providers = new Map<AuthIdentityProvider, AuthProvider>()

  register(provider: AuthProvider): void {
    this.providers.set(provider.id, provider)
  }

  async get(provider: AuthIdentityProvider): Promise<AuthProvider | undefined> {
    return this.providers.get(provider)
  }
}
