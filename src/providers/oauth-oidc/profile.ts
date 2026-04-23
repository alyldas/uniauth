import type { ProviderIdentityAssertion } from '../../domain/types.js'
import { optionalProp } from '../../utils/optional.js'
import { readString, requireNonBlankString } from './support.js'
import type { OAuthOidcProfileMapperInput } from './types.js'

export function mapOAuthOidcProfileToAssertion(
  input: OAuthOidcProfileMapperInput,
): ProviderIdentityAssertion {
  const subject = requireNonBlankString(
    input.profile.subject,
    'OAuth/OIDC profile subject is required.',
  )
  const email = readString(input.profile.email)
  const phone = readString(input.profile.phone)
  const metadata = buildOAuthOidcAssertionMetadata(input.profile)

  return {
    provider: input.provider,
    providerUserId: subject,
    ...(email ? { email, emailVerified: input.profile.emailVerified === true } : {}),
    ...(phone ? { phone, phoneVerified: input.profile.phoneVerified === true } : {}),
    ...optionalProp('displayName', readString(input.profile.displayName)),
    ...optionalProp('metadata', metadata),
  }
}

function buildOAuthOidcAssertionMetadata(
  profile: OAuthOidcProfileMapperInput['profile'],
): Record<string, unknown> | undefined {
  const metadata = {
    ...optionalProp('issuer', readString(profile.issuer)),
    ...optionalProp('preferredUsername', readString(profile.preferredUsername)),
    ...optionalProp('pictureUrl', readString(profile.pictureUrl)),
    ...optionalProp('locale', readString(profile.locale)),
    ...profile.metadata,
  }

  return Object.keys(metadata).length > 0 ? metadata : undefined
}
