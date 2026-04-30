import type { ProviderIdentityAssertion } from '../../src'

export const now = new Date('2026-01-01T00:00:00.000Z')

export function assertion(
  input: Partial<ProviderIdentityAssertion> = {},
): ProviderIdentityAssertion {
  return {
    provider: input.provider ?? 'email',
    providerUserId: input.providerUserId ?? 'alice',
    email: input.email ?? 'Alice@Example.com',
    emailVerified: input.emailVerified ?? true,
    displayName: input.displayName ?? 'Alice',
    ...(input.phone ? { phone: input.phone } : {}),
    ...(input.phoneVerified !== undefined ? { phoneVerified: input.phoneVerified } : {}),
  }
}
