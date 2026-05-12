import type { FinishInput } from '../../domain/types.js'
import type { AuthProvider } from '../../contracts.js'
import { invalidInput } from '../../errors.js'
import { optionalProp } from '../../utils/optional.js'
import { mapOAuthOidcProfileToAssertion } from './profile.js'
import {
  isRecord,
  normalizeMetadataRecord,
  readFinishPayload,
  readString,
  requireNonBlankString,
} from './support.js'
import type {
  OAuthOidcAuthorizationCodeExchangeInput,
  OAuthOidcFetchProfileInput,
  OAuthOidcProviderOptions,
  OAuthOidcTokenSet,
} from './types.js'

export function createOAuthOidcProvider(options: OAuthOidcProviderOptions): AuthProvider {
  const providerId = requireNonBlankString(
    options.providerId,
    'OAuth/OIDC provider id is required.',
  )
  const mapProfile = options.mapProfile ?? mapOAuthOidcProfileToAssertion

  return {
    id: providerId,
    async finish(finishInput) {
      const exchangeInput = readAuthorizationCodeExchangeInput(finishInput)
      const tokens = normalizeTokenSet(await options.client.exchangeCode(exchangeInput))
      const profile = await options.client.fetchProfile(
        readFetchProfileInput(tokens, exchangeInput),
      )

      return mapProfile({
        provider: providerId,
        profile,
        finishInput,
        exchangeInput,
      })
    },
  }
}

function readAuthorizationCodeExchangeInput(
  input: FinishInput,
): OAuthOidcAuthorizationCodeExchangeInput {
  const payload = readFinishPayload(input)
  const code = readString(input.code) ?? readString(payload.code)

  if (!code) {
    throw invalidInput('OAuth/OIDC authorization code is required.')
  }

  const state = readString(input.state) ?? readString(payload.state)
  const metadata = readAuthorizationCodeMetadata(input, payload)

  return {
    code,
    ...optionalProp('state', state),
    ...optionalProp('redirectUri', readString(payload.redirectUri)),
    ...optionalProp('codeVerifier', readString(payload.codeVerifier)),
    ...optionalProp('metadata', metadata),
  }
}

function readAuthorizationCodeMetadata(
  input: FinishInput,
  payload: Record<string, unknown>,
): Record<string, unknown> | undefined {
  if (Object.prototype.hasOwnProperty.call(payload, 'metadata')) {
    return normalizeMetadataRecord(
      payload.metadata,
      'OAuth/OIDC finish metadata must be a plain object.',
    )
  }

  return normalizeMetadataRecord(
    input.metadata,
    'OAuth/OIDC finish metadata must be a plain object.',
  )
}

function readFetchProfileInput(
  tokens: OAuthOidcTokenSet,
  exchangeInput: OAuthOidcAuthorizationCodeExchangeInput,
): OAuthOidcFetchProfileInput {
  return {
    tokens,
    ...optionalProp('state', exchangeInput.state),
    ...optionalProp('metadata', exchangeInput.metadata),
  }
}

function normalizeTokenSet(tokens: OAuthOidcTokenSet): OAuthOidcTokenSet {
  if (!isRecord(tokens)) {
    throw invalidInput('OAuth/OIDC token set is required.')
  }

  const tokenSet = tokens as OAuthOidcTokenSet
  const accessToken = readString(tokenSet.accessToken)
  const refreshToken = readString(tokenSet.refreshToken)
  const idToken = readString(tokenSet.idToken)

  if (!accessToken && !idToken) {
    throw invalidInput('OAuth/OIDC token set must include an access token or id token.')
  }

  return {
    ...optionalProp('accessToken', accessToken),
    ...optionalProp('refreshToken', refreshToken),
    ...optionalProp('idToken', idToken),
    ...optionalProp('tokenType', readString(tokenSet.tokenType)),
    ...optionalProp('expiresAt', tokenSet.expiresAt),
    ...optionalProp('scopes', tokenSet.scopes),
  }
}
