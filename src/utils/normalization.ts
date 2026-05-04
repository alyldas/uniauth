import type { AuthNormalizer, CreateAuthNormalizerOptions } from '../contracts.js'
export type {
  AuthNormalizer,
  AuthTargetNormalizer,
  AuthValueNormalizer,
  CreateAuthNormalizerOptions,
} from '../contracts.js'

export function normalizeEmail(email: string): string {
  return email.trim().toLowerCase()
}

export function normalizePhone(phone: string): string {
  return phone.replace(/[\s().-]+/g, '').trim()
}

export function normalizeTarget(target: string): string {
  return defaultNormalizeTarget(target, {
    normalizeEmail,
    normalizePhone,
  })
}

export function createAuthNormalizer(options: CreateAuthNormalizerOptions = {}): AuthNormalizer {
  const helpers = {
    normalizeEmail: options.normalizeEmail ?? normalizeEmail,
    normalizePhone: options.normalizePhone ?? normalizePhone,
  }
  const normalizeTargetHandler = options.normalizeTarget ?? defaultNormalizeTarget

  return {
    normalizeEmail: helpers.normalizeEmail,
    normalizePhone: helpers.normalizePhone,
    normalizeTarget: (target) => normalizeTargetHandler(target, helpers),
  }
}

export const compatibilityAuthNormalizer = createAuthNormalizer()

function defaultNormalizeTarget(
  target: string,
  helpers: Pick<AuthNormalizer, 'normalizeEmail' | 'normalizePhone'>,
): string {
  const trimmed = target.trim()

  if (!trimmed) {
    return ''
  }

  if (trimmed.includes('@')) {
    return helpers.normalizeEmail(trimmed)
  }

  if (isPhoneLikeTarget(trimmed)) {
    return helpers.normalizePhone(trimmed)
  }

  return trimmed
}

function isPhoneLikeTarget(target: string): boolean {
  return /[0-9]/u.test(target) && /^[+\d\s().-]+$/u.test(target)
}
