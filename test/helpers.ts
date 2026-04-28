import {
  AuthIdentityStatus,
  asIdentityId,
  asUserId,
  createAuthNormalizer,
  invalidInput,
  normalizeEmail,
  type AuthNormalizer,
  type AuthIdentity,
  type ProviderIdentityAssertion,
  type User,
} from '../src'

export const now = new Date('2026-01-01T00:00:00.000Z')

const strictEmailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/u
const strictE164Pattern = /^\+[1-9]\d{7,14}$/u

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
    ...(input.trust ? { trust: input.trust } : {}),
    ...(input.metadata ? { metadata: input.metadata } : {}),
  }
}

export function rateLimitKey(...parts: readonly string[]): string {
  return parts.join('\u0000')
}

export function createStrictNormalizer(): AuthNormalizer {
  return createAuthNormalizer({
    normalizeEmail(email) {
      const normalized = normalizeEmail(email)

      if (!normalized || !strictEmailPattern.test(normalized)) {
        throw invalidInput('Email is invalid.')
      }

      return normalized
    },
    normalizePhone(phone) {
      const trimmed = phone.trim()
      const digits = trimmed.replace(/\D+/g, '')
      const normalized = trimmed.startsWith('+')
        ? `+${digits}`
        : digits.length === 10
          ? `+1${digits}`
          : digits.length === 11 && digits.startsWith('1')
            ? `+${digits}`
            : ''

      if (!strictE164Pattern.test(normalized)) {
        throw invalidInput('Phone is invalid.')
      }

      return normalized
    },
  })
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
    ...(input.trust ? { trust: input.trust } : {}),
    ...(input.disabledAt ? { disabledAt: input.disabledAt } : {}),
    ...(input.metadata ? { metadata: input.metadata } : {}),
  }
}
