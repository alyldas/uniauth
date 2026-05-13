import { invalidInput } from '../../errors.js'
import { optionalProp } from '../../utils/optional.js'
import {
  isRecord,
  normalizeMetadataRecord,
  normalizeOptionalDate,
  normalizeOptionalStringArray,
  readString,
  requireNonBlankString,
} from './support.js'
import type {
  CreateOAuthOidcTokenRecordInput,
  OAuthOidcTokenBinding,
  OAuthOidcTokenRecord,
  OAuthOidcTokenSet,
} from './types.js'

export function createOAuthOidcTokenRecord(
  input: CreateOAuthOidcTokenRecordInput,
): OAuthOidcTokenRecord {
  const provider = requireNonBlankString(
    input.provider,
    'OAuth/OIDC token record provider is required.',
  )
  const providerUserId = requireNonBlankString(
    input.providerUserId,
    'OAuth/OIDC token record provider user id is required.',
  )
  const binding = normalizeBinding(input.binding)
  const tokens = normalizeTokenSet(input.tokens)
  const metadata = normalizeMetadata(input.metadata)

  return {
    provider,
    providerUserId,
    binding,
    ...tokens,
    ...optionalProp('metadata', metadata),
  }
}

function normalizeBinding(binding: OAuthOidcTokenBinding): OAuthOidcTokenBinding {
  if (!isRecord(binding)) {
    throw invalidInput('OAuth/OIDC token record binding is required.')
  }

  return {
    kind: requireNonBlankString(binding.kind, 'OAuth/OIDC token record binding kind is required.'),
    value: requireNonBlankString(
      binding.value,
      'OAuth/OIDC token record binding value is required.',
    ),
  }
}

function normalizeTokenSet(
  tokens: OAuthOidcTokenSet,
): Omit<OAuthOidcTokenRecord, 'provider' | 'providerUserId' | 'binding' | 'metadata'> {
  if (!isRecord(tokens)) {
    throw invalidInput('OAuth/OIDC token set is required.')
  }

  const accessToken = readString(tokens.accessToken)
  const refreshToken = readString(tokens.refreshToken)
  const idToken = readString(tokens.idToken)
  const tokenType = readString(tokens.tokenType)
  const expiresAt = normalizeOptionalDate(
    tokens.expiresAt,
    'OAuth/OIDC token expiration time is invalid.',
  )
  const scopes = normalizeOptionalStringArray(
    tokens.scopes,
    'OAuth/OIDC token scopes must be an array of strings.',
  )

  if (!accessToken && !refreshToken && !idToken) {
    throw invalidInput(
      'OAuth/OIDC token record must include an access token, refresh token, or id token.',
    )
  }

  return {
    ...optionalProp('accessToken', accessToken),
    ...optionalProp('refreshToken', refreshToken),
    ...optionalProp('idToken', idToken),
    ...optionalProp('tokenType', tokenType),
    ...optionalProp('expiresAt', expiresAt),
    ...optionalProp('scopes', scopes),
  }
}

function normalizeMetadata(value: unknown): Record<string, unknown> | undefined {
  const metadata = normalizeMetadataRecord(
    value,
    'OAuth/OIDC token record metadata must be a plain object.',
  )

  return metadata ? { ...metadata } : undefined
}
