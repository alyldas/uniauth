import type { AuthIdentityProvider, ProviderIdentityAssertion } from '../domain/types.js'
import type { AuthProvider, ProviderRegistry } from '../contracts.js'
import { invalidInput } from '../errors.js'

export class StaticAuthProvider implements AuthProvider {
  readonly id: AuthIdentityProvider
  private assertion: ProviderIdentityAssertion

  constructor(id: AuthIdentityProvider, assertion: Omit<ProviderIdentityAssertion, 'provider'>) {
    if (typeof id !== 'string' || !id.trim()) {
      throw invalidInput('Static auth provider id is required.')
    }

    if (!isRecord(assertion)) {
      throw invalidInput('Static auth provider assertion is required.')
    }

    this.id = id
    this.assertion = { provider: id, ...assertion }
  }

  async finish(): Promise<ProviderIdentityAssertion> {
    return this.assertion
  }

  /** Replace the next assertion returned by this test provider. */
  setAssertion(assertion: Omit<ProviderIdentityAssertion, 'provider'>): void {
    if (!isRecord(assertion)) {
      throw invalidInput('Static auth provider assertion is required.')
    }

    this.assertion = { provider: this.id, ...assertion }
  }
}

export class InMemoryProviderRegistry implements ProviderRegistry {
  private readonly providers = new Map<AuthIdentityProvider, AuthProvider>()

  register(provider: AuthProvider): void {
    if (!isRecord(provider) || typeof provider.id !== 'string' || !provider.id.trim()) {
      throw invalidInput('Provider registry provider id is required.')
    }

    if (typeof provider.finish !== 'function') {
      throw invalidInput('Provider registry provider finish is required.')
    }

    this.providers.set(provider.id, provider)
  }

  async get(provider: AuthIdentityProvider): Promise<AuthProvider | undefined> {
    return this.providers.get(provider)
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}
