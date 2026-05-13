import { optionalProp } from '../optional.js'
import type { AuthServiceRuntime } from '../runtime.js'
import { normalizeMetadataRecord } from '../metadata.js'
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
  const provider = normalizeRequiredClaim(assertion.provider, 'Provider is required.')
  const providerUserId = normalizeRequiredClaim(
    assertion.providerUserId,
    'Provider user id is required.',
  )

  if (!provider || !providerUserId) {
    throw invalidInput('Provider and provider user id are required.')
  }

  if (hasControlCharacter(provider) || hasControlCharacter(providerUserId)) {
    throw invalidInput('Provider and provider user id cannot contain control characters.')
  }

  const email = normalizeOptionalClaim(assertion.email, runtime.normalizer.normalizeEmail)
  const phone = normalizeOptionalClaim(assertion.phone, runtime.normalizer.normalizePhone)
  const displayName = normalizeOptionalClaim(assertion.displayName, (value) => value)

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
      normalizeMetadataRecord(assertion.metadata, 'Provider assertion metadata'),
    ),
  }
}

function normalizeRequiredClaim(value: unknown, message: string): string {
  if (typeof value !== 'string') {
    throw invalidInput(message)
  }

  return value.trim()
}

function hasControlCharacter(value: string): boolean {
  return /[\u0000-\u001f\u007f]/u.test(value)
}

function normalizeOptionalClaim(
  value: unknown,
  normalize: (value: string) => string,
): string | undefined {
  if (value === undefined) {
    return undefined
  }

  if (typeof value !== 'string') {
    throw invalidInput('Provider assertion optional claims must be strings.')
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
    ...optionalProp('metadata', normalizeMetadataRecord(trust.metadata, 'Provider trust metadata')),
  }
}
