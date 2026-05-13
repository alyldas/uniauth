import type { AuthIdentityProvider, ProviderIdentityAssertion } from '../domain/types.js'
import type { AuthProvider, ProviderRegistry } from '../contracts.js'
import { invalidInput } from '../errors.js'

export class StaticAuthProvider implements AuthProvider {
  readonly id: AuthIdentityProvider
  private assertion: ProviderIdentityAssertion

  constructor(id: AuthIdentityProvider, assertion: Omit<ProviderIdentityAssertion, 'provider'>) {
    const providerId = normalizeProviderId(id)

    if (!providerId) {
      throw invalidInput('Static auth provider id is required.')
    }

    if (!isRecord(assertion)) {
      throw invalidInput('Static auth provider assertion is required.')
    }

    this.id = providerId
    this.assertion = { provider: providerId, ...assertion }
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
    if (!isRecord(provider)) {
      throw invalidInput('Provider registry provider id is required.')
    }

    const providerId = normalizeProviderId(provider.id)

    if (!providerId) {
      throw invalidInput('Provider registry provider id is required.')
    }

    if (typeof provider.finish !== 'function') {
      throw invalidInput('Provider registry provider finish is required.')
    }

    this.providers.set(providerId, provider)
  }

  async get(provider: AuthIdentityProvider): Promise<AuthProvider | undefined> {
    const providerId = normalizeProviderId(provider)

    if (!providerId) {
      throw invalidInput('Provider registry provider id is required.')
    }

    return this.providers.get(providerId)
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function normalizeProviderId(value: unknown): AuthIdentityProvider | '' {
  if (typeof value !== 'string') {
    return ''
  }

  return value.trim() as AuthIdentityProvider | ''
}
