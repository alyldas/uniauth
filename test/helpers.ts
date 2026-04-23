import {
  AuthIdentityStatus,
  asIdentityId,
  asUserId,
  type AuthIdentity,
  type ProviderIdentityAssertion,
  type User,
} from '../src'

export const now = new Date('2026-01-01T00:00:00.000Z')

export function assertion(
  input: Partial<ProviderIdentityAssertion> = {},
): ProviderIdentityAssertion {
  return {
    provider: input.provider ?? 'email',
    providerUserId: input.providerUserId ?? 'alice',
    ...(input.email ? { email: input.email } : {}),
    ...(input.emailVerified !== undefined ? { emailVerified: input.emailVerified } : {}),
    ...(input.phone ? { phone: input.phone } : {}),
    ...(input.phoneVerified !== undefined ? { phoneVerified: input.phoneVerified } : {}),
    ...(input.displayName ? { displayName: input.displayName } : {}),
    ...(input.metadata ? { metadata: input.metadata } : {}),
  }
}

export function rateLimitKey(...parts: readonly string[]): string {
  return parts.join('\u0000')
}

export function user(id = 'user-1'): User {
  return {
    id: asUserId(id),
    createdAt: now,
    updatedAt: now,
  }
}

export function identity(input: Partial<AuthIdentity> = {}): AuthIdentity {
  return {
    id: input.id ?? asIdentityId('identity-1'),
    userId: input.userId ?? asUserId('user-1'),
    provider: input.provider ?? 'email',
    providerUserId: input.providerUserId ?? 'alice',
    status: input.status ?? AuthIdentityStatus.Active,
    createdAt: input.createdAt ?? now,
    updatedAt: input.updatedAt ?? now,
    ...(input.email ? { email: input.email } : {}),
    ...(input.emailVerified !== undefined ? { emailVerified: input.emailVerified } : {}),
    ...(input.phone ? { phone: input.phone } : {}),
    ...(input.phoneVerified !== undefined ? { phoneVerified: input.phoneVerified } : {}),
    ...(input.disabledAt ? { disabledAt: input.disabledAt } : {}),
    ...(input.metadata ? { metadata: input.metadata } : {}),
  }
}
