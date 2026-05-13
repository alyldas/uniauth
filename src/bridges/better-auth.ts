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
} from './support.js'

export interface BetterAuthAccount {
  readonly providerId?: string
  readonly accountId?: string
}

export interface BetterAuthOAuthProfile {
  readonly id?: string
  readonly email?: string
  readonly emailVerified?: boolean | string
  readonly name?: string
  readonly image?: string
}

export interface BetterAuthUser {
  readonly email?: string
  readonly emailVerified?: boolean | string
  readonly name?: string
  readonly image?: string
}

export interface BetterAuthOAuthAssertionInput {
  readonly providerId?: AuthIdentityProvider
  readonly account?: BetterAuthAccount
  readonly profile?: BetterAuthOAuthProfile
  readonly user?: BetterAuthUser
  readonly trust?: ProviderTrustContext
  readonly metadata?: Record<string, unknown>
}

export function mapBetterAuthOAuthToAssertion(
  input: BetterAuthOAuthAssertionInput,
): ProviderIdentityAssertion {
  if (!isPlainRecord(input as unknown)) {
    throw invalidInput('Better Auth bridge input is required.')
  }

  const frameworkProviderId = readString(input.account?.providerId)
  const provider = readString(input.providerId) ?? frameworkProviderId

  if (!provider) {
    throw invalidInput('Better Auth bridge providerId is required.')
  }

  const accountId = readString(input.account?.accountId)
  const profileId = readString(input.profile?.id)
  const providerUserId = accountId ?? profileId

  if (!providerUserId) {
    throw invalidInput('Better Auth accountId or profile.id is required.')
  }

  requireMatchingStrings(
    accountId,
    profileId,
    'Better Auth accountId and profile.id must match when both are provided.',
  )

  const email = readString(input.profile?.email) ?? readString(input.user?.email)
  const emailVerified =
    readBooleanLike(input.profile?.emailVerified) ?? readBooleanLike(input.user?.emailVerified)
  const displayName = readString(input.profile?.name) ?? readString(input.user?.name)
  const metadata = buildMetadata(
    {
      frameworkProviderId:
        frameworkProviderId && provider !== frameworkProviderId ? frameworkProviderId : undefined,
      pictureUrl: readString(input.profile?.image) ?? readString(input.user?.image),
    },
    input.metadata,
  )

  return {
    provider,
    providerUserId,
    ...(email ? { email, emailVerified: emailVerified === true } : {}),
    ...optionalProp('displayName', displayName),
    ...optionalProp('trust', input.trust),
    ...optionalProp('metadata', metadata),
  }
}
