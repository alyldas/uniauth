import type { AuthNormalizer, CreateAuthNormalizerOptions } from '../contracts.js'
export type {
  AuthNormalizer,
  AuthTargetNormalizer,
  AuthValueNormalizer,
  CreateAuthNormalizerOptions,
} from '../contracts.js'

export function normalizeEmail(email: string): string {
  return requireNormalizerString(email, 'Email must be a string.').trim().toLowerCase()
}

export function normalizePhone(phone: string): string {
  return requireNormalizerString(phone, 'Phone must be a string.')
    .replace(/[\s().-]+/g, '')
    .trim()
}

export function normalizeTarget(target: string): string {
  return defaultNormalizeTarget(target, {
    normalizeEmail,
    normalizePhone,
  })
}

export function createAuthNormalizer(options: CreateAuthNormalizerOptions = {}): AuthNormalizer {
  if (!isNormalizerOptions(options)) {
    throw new Error('Normalizer options must be a plain object.')
  }

  if (options.normalizeEmail !== undefined && typeof options.normalizeEmail !== 'function') {
    throw new Error('Email normalizer must be a function.')
  }

  if (options.normalizePhone !== undefined && typeof options.normalizePhone !== 'function') {
    throw new Error('Phone normalizer must be a function.')
  }

  if (options.normalizeTarget !== undefined && typeof options.normalizeTarget !== 'function') {
    throw new Error('Target normalizer must be a function.')
  }

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
  const trimmed = requireNormalizerString(target, 'Target must be a string.').trim()

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

function isNormalizerOptions(value: unknown): value is CreateAuthNormalizerOptions {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    return false
  }

  const prototype = Object.getPrototypeOf(value)
  return prototype === Object.prototype || prototype === null
}

function requireNormalizerString(value: string, message: string): string {
  if (typeof value !== 'string') {
    throw new Error(message)
  }

  return value
}
