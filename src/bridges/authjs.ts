import type {
  AuthIdentityProvider,
  ProviderIdentityAssertion,
  ProviderTrustContext,
} from '../domain/types.js'
import { invalidInput } from '../errors.js'
import { optionalProp } from '../utils/optional.js'
import {
  buildMetadata,
  isPlainRecord,
  readBooleanLike,
  readString,
  requireMatchingStrings,
  requireNonBlankString,
} from './support.js'

const AUTH_JS_OAUTH_ACCOUNT_TYPES = new Set(['oauth', 'oidc'])

export interface AuthJsOAuthAccount {
  readonly provider: string
  readonly providerAccountId: string
  readonly type?: string
}

export interface AuthJsOAuthProfile {
  readonly sub?: string
  readonly id?: string
  readonly name?: string
  readonly email?: string
  readonly email_verified?: boolean | string
  readonly phone_number?: string
  readonly phone_number_verified?: boolean | string
  readonly preferred_username?: string
  readonly picture?: string
  readonly locale?: string
}

export interface AuthJsUser {
  readonly name?: string
  readonly email?: string
  readonly image?: string
  readonly emailVerified?: boolean | string
}

export interface AuthJsOAuthAssertionInput {
  readonly providerId?: AuthIdentityProvider
  readonly account: AuthJsOAuthAccount
  readonly profile?: AuthJsOAuthProfile
  readonly user?: AuthJsUser
  readonly trust?: ProviderTrustContext
  readonly metadata?: Record<string, unknown>
}

export function mapAuthJsOAuthToAssertion(
  input: AuthJsOAuthAssertionInput,
): ProviderIdentityAssertion {
  if (!isPlainRecord(input as unknown)) {
    throw invalidInput('Auth.js bridge input is required.')
  }

  if (!isPlainRecord(input.account as unknown)) {
    throw invalidInput('Auth.js account is required.')
  }

  const accountType = readString(input.account.type)?.toLowerCase()

  if (accountType && !AUTH_JS_OAUTH_ACCOUNT_TYPES.has(accountType)) {
    throw invalidInput('Auth.js bridge only accepts oauth or oidc accounts.')
  }

  const frameworkProviderId = requireNonBlankString(
    input.account.provider,
    'Auth.js account provider is required.',
  )
  const provider = readString(input.providerId) ?? frameworkProviderId
  const providerUserId = requireNonBlankString(
    input.account.providerAccountId,
    'Auth.js account providerAccountId is required.',
  )
  const profileSubject = readString(input.profile?.sub) ?? readString(input.profile?.id)

  requireMatchingStrings(
    providerUserId,
    profileSubject,
    'Auth.js account providerAccountId and profile subject must match.',
  )

  const email = readString(input.profile?.email) ?? readString(input.user?.email)
  const emailVerified =
    readBooleanLike(input.profile?.email_verified) ?? readBooleanLike(input.user?.emailVerified)
  const phone = readString(input.profile?.phone_number)
  const phoneVerified = readBooleanLike(input.profile?.phone_number_verified)
  const displayName =
    readString(input.profile?.name) ??
    readString(input.user?.name) ??
    readString(input.profile?.preferred_username)
  const metadata = buildMetadata(
    {
      frameworkProviderId: provider !== frameworkProviderId ? frameworkProviderId : undefined,
      preferredUsername: readString(input.profile?.preferred_username),
      pictureUrl: readString(input.profile?.picture) ?? readString(input.user?.image),
      locale: readString(input.profile?.locale),
    },
    input.metadata,
  )

  return {
    provider,
    providerUserId,
    ...(email ? { email, emailVerified: emailVerified === true } : {}),
    ...(phone ? { phone, phoneVerified: phoneVerified === true } : {}),
    ...optionalProp('displayName', displayName),
    ...optionalProp('trust', input.trust),
    ...optionalProp('metadata', metadata),
  }
}
