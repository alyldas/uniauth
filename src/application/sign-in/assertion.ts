import { optionalProp } from '../optional.js'
import type { AuthServiceRuntime } from '../runtime.js'
import {
  ProviderTrustLevel,
  type FinishInput,
  type ProviderIdentityAssertion,
  type ProviderTrustContext,
} from '../../domain/types.js'
import { UniAuthError, UniAuthErrorCode, invalidInput } from '../../errors.js'

export async function resolveAssertion(
  runtime: AuthServiceRuntime,
  input: {
    readonly assertion?: ProviderIdentityAssertion
    readonly provider?: string
    readonly finishInput?: FinishInput
  },
): Promise<ProviderIdentityAssertion> {
  if (input.assertion) {
    return normalizeAssertion(runtime, input.assertion)
  }

  if (!input.provider || !input.finishInput) {
    throw invalidInput('Either assertion or provider finish input is required.')
  }

  if (!runtime.providerRegistry) {
    throw new UniAuthError(UniAuthErrorCode.ProviderNotFound, 'Auth provider was not found.')
  }

  const provider = await runtime.providerRegistry.get(input.provider)

  if (!provider) {
    throw new UniAuthError(UniAuthErrorCode.ProviderNotFound, 'Auth provider was not found.')
  }

  return normalizeAssertion(runtime, await provider.finish(input.finishInput))
}

export function normalizeAssertion(
  runtime: Pick<AuthServiceRuntime, 'normalizer'>,
  assertion: Partial<ProviderIdentityAssertion>,
): ProviderIdentityAssertion {
  const provider = assertion.provider?.trim() ?? ''
  const providerUserId = assertion.providerUserId?.trim() ?? ''

  if (!provider || !providerUserId) {
    throw invalidInput('Provider and provider user id are required.')
  }

  if (hasControlCharacter(provider) || hasControlCharacter(providerUserId)) {
    throw invalidInput('Provider and provider user id cannot contain control characters.')
  }

  const email = normalizeOptionalClaim(assertion.email, runtime.normalizer.normalizeEmail)
  const phone = normalizeOptionalClaim(assertion.phone, runtime.normalizer.normalizePhone)
  const displayName = assertion.displayName?.trim() || undefined

  return {
    provider,
    providerUserId,
    ...(email
      ? {
          email,
          emailVerified: assertion.emailVerified === true,
        }
      : {}),
    ...(phone
      ? {
          phone,
          phoneVerified: assertion.phoneVerified === true,
        }
      : {}),
    ...optionalProp('displayName', displayName),
    ...optionalProp('trust', normalizeProviderTrust(assertion.trust)),
    ...optionalProp(
      'metadata',
      normalizeMetadata(assertion.metadata, 'Provider assertion metadata'),
    ),
  }
}

function hasControlCharacter(value: string): boolean {
  return /[\u0000-\u001f\u007f]/u.test(value)
}

function normalizeOptionalClaim(
  value: string | undefined,
  normalize: (value: string) => string,
): string | undefined {
  if (value === undefined) {
    return undefined
  }

  const trimmed = value.trim()

  if (!trimmed) {
    return undefined
  }

  return normalize(trimmed)
}

function normalizeProviderTrust(
  trust: ProviderIdentityAssertion['trust'],
): ProviderTrustContext | undefined {
  if (!trust) {
    return undefined
  }

  if (typeof trust.level !== 'string') {
    throw invalidInput('Provider trust level must be a string.')
  }

  const level = trust.level.trim() as ProviderTrustLevel

  if (
    level !== ProviderTrustLevel.Trusted &&
    level !== ProviderTrustLevel.Neutral &&
    level !== ProviderTrustLevel.Untrusted
  ) {
    throw invalidInput('Provider trust level must be trusted, neutral, or untrusted.')
  }

  if (trust.signals !== undefined && !Array.isArray(trust.signals)) {
    throw invalidInput('Provider trust signals must be an array of strings.')
  }

  const signals = trust.signals
    ?.map((signal) => {
      if (typeof signal !== 'string') {
        throw invalidInput('Provider trust signals must be an array of strings.')
      }

      return signal.trim()
    })
    .filter((signal) => signal.length > 0)

  return {
    level,
    ...(signals && signals.length > 0 ? { signals: [...new Set(signals)] } : {}),
    ...optionalProp('metadata', normalizeMetadata(trust.metadata, 'Provider trust metadata')),
  }
}

function normalizeMetadata(
  metadata: Record<string, unknown> | undefined,
  name: string,
): Record<string, unknown> | undefined {
  if (metadata === undefined) {
    return undefined
  }

  if (!isPlainObject(metadata)) {
    throw invalidInput(`${name} must be a plain object.`)
  }

  return metadata
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    return false
  }

  const prototype = Object.getPrototypeOf(value) as unknown
  return prototype === Object.prototype || prototype === null
}
