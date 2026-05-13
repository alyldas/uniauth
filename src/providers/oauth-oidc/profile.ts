import type { ProviderIdentityAssertion } from '../../domain/types.js'
import { invalidInput } from '../../errors.js'
import { optionalProp } from '../../utils/optional.js'
import { isRecord, normalizeMetadataRecord, readString, requireNonBlankString } from './support.js'
import type { OAuthOidcProfileMapperInput } from './types.js'

export function mapOAuthOidcProfileToAssertion(
  input: OAuthOidcProfileMapperInput,
): ProviderIdentityAssertion {
  if (!isRecord(input)) {
    throw invalidInput('OAuth/OIDC profile mapper input is required.')
  }

  if (!isRecord(input.profile)) {
    throw invalidInput('OAuth/OIDC profile is required.')
  }

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
  const profileMetadata = normalizeMetadataRecord(
    profile.metadata,
    'OAuth/OIDC profile metadata must be a plain object.',
  )
  const metadata = {
    ...optionalProp('issuer', readString(profile.issuer)),
    ...optionalProp('preferredUsername', readString(profile.preferredUsername)),
    ...optionalProp('pictureUrl', readString(profile.pictureUrl)),
    ...optionalProp('locale', readString(profile.locale)),
    ...profileMetadata,
  }

  return Object.keys(metadata).length > 0 ? metadata : undefined
}
