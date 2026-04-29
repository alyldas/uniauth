import type {
  AuthIdentityProvider,
  ExtensibleString,
  FinishInput,
  ProviderIdentityAssertion,
} from '../../domain/types.js'

export interface OAuthOidcAuthorizationCodeExchangeInput {
  readonly code: string
  readonly state?: string
  readonly redirectUri?: string
  readonly codeVerifier?: string
  readonly metadata?: Record<string, unknown>
}

export interface OAuthOidcTokenSet {
  readonly accessToken?: string
  readonly refreshToken?: string
  readonly idToken?: string
  readonly tokenType?: string
  readonly expiresAt?: Date
  readonly scopes?: readonly string[]
}

export const OAuthOidcTokenBindingKind = {
  CallbackState: 'callback-state',
  Session: 'session',
  Identity: 'identity',
  User: 'user',
} as const

export type OAuthOidcTokenBindingKind = ExtensibleString<
  (typeof OAuthOidcTokenBindingKind)[keyof typeof OAuthOidcTokenBindingKind]
>

export interface OAuthOidcTokenBinding {
  readonly kind: OAuthOidcTokenBindingKind
  readonly value: string
}

export interface OAuthOidcTokenRecord {
  readonly provider: AuthIdentityProvider
  readonly providerUserId: string
  readonly binding: OAuthOidcTokenBinding
  readonly accessToken?: string
  readonly refreshToken?: string
  readonly idToken?: string
  readonly tokenType?: string
  readonly expiresAt?: Date
  readonly scopes?: readonly string[]
  readonly metadata?: Record<string, unknown>
}

export interface CreateOAuthOidcTokenRecordInput {
  readonly provider: AuthIdentityProvider
  readonly providerUserId: string
  readonly binding: OAuthOidcTokenBinding
  readonly tokens: OAuthOidcTokenSet
  readonly metadata?: Record<string, unknown>
}

export interface OAuthOidcFetchProfileInput {
  readonly tokens: OAuthOidcTokenSet
  readonly state?: string
  readonly metadata?: Record<string, unknown>
}

export interface OAuthOidcClient {
  exchangeCode(input: OAuthOidcAuthorizationCodeExchangeInput): Promise<OAuthOidcTokenSet>
  fetchProfile(input: OAuthOidcFetchProfileInput): Promise<OAuthOidcProfile>
}

export interface OAuthOidcProfile {
  readonly subject: string
  readonly email?: string
  readonly emailVerified?: boolean
  readonly phone?: string
  readonly phoneVerified?: boolean
  readonly displayName?: string
  readonly preferredUsername?: string
  readonly pictureUrl?: string
  readonly locale?: string
  readonly issuer?: string
  readonly metadata?: Record<string, unknown>
}

export interface OAuthOidcProviderOptions {
  readonly providerId: AuthIdentityProvider
  readonly client: OAuthOidcClient
  readonly mapProfile?: OAuthOidcProfileMapper
}

export interface OAuthOidcProfileMapperInput {
  readonly provider: AuthIdentityProvider
  readonly profile: OAuthOidcProfile
  readonly finishInput: FinishInput
  readonly exchangeInput: OAuthOidcAuthorizationCodeExchangeInput
}

export type OAuthOidcProfileMapper = (
  input: OAuthOidcProfileMapperInput,
) => ProviderIdentityAssertion | Promise<ProviderIdentityAssertion>
