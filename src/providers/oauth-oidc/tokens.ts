import { invalidInput } from '../../errors.js'
import { optionalProp } from '../../utils/optional.js'
import { isRecord, readString, requireNonBlankString } from './support.js'
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
  const expiresAt = normalizeExpiresAt(tokens.expiresAt)
  const scopes = normalizeScopes(tokens.scopes)

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

function normalizeExpiresAt(value: unknown): Date | undefined {
  if (value === undefined) {
    return undefined
  }

  if (!(value instanceof Date) || Number.isNaN(value.getTime())) {
    throw invalidInput('OAuth/OIDC token expiration time is invalid.')
  }

  return value
}

function normalizeScopes(value: unknown): readonly string[] | undefined {
  if (value === undefined) {
    return undefined
  }

  if (!Array.isArray(value) || value.some((scope) => typeof scope !== 'string')) {
    throw invalidInput('OAuth/OIDC token scopes must be an array of strings.')
  }

  const scopes = [...new Set(value.map((scope) => scope.trim()).filter(Boolean))]
  return scopes.length > 0 ? scopes : undefined
}

function normalizeMetadata(value: unknown): Record<string, unknown> | undefined {
  if (value === undefined) {
    return undefined
  }

  if (!isRecord(value)) {
    throw invalidInput('OAuth/OIDC token record metadata must be a plain object.')
  }

  return { ...value }
}
