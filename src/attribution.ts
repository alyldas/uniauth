import packageJson from '../package.json'

interface PackageMetadata {
  readonly name: string
  readonly license: string
  readonly author: {
    readonly name: string
    readonly email: string
  }
  readonly repository: {
    readonly url: string
  }
}

function formatPackageLicenseName(license: string): string {
  return license
    .replace(/^PolyForm-/, 'PolyForm ')
    .replace(/-(\d+\.\d+\.\d+)$/, ' License $1')
    .replaceAll('-', ' ')
}

function normalizeRepositoryUrl(url: string): string {
  return url.replace(/^git\+/, '').replace(/\.git$/, '')
}

export interface UniAuthAttributionDetails {
  readonly packageName: string
  readonly displayName: string
  readonly author: string
  readonly copyright: string
  readonly license: string
  readonly notice: string
  readonly repositoryUrl: string
  readonly contactEmail: string
}

export interface UniAuthAttributionNoticeOptions {
  readonly productName?: string
  readonly includeLicense?: boolean
  readonly includeContact?: boolean
}

const packageMetadata = packageJson as PackageMetadata
const displayName = packageMetadata.name.replace(/^@[^/]+\//, '')
const displayLicense = formatPackageLicenseName(packageMetadata.license)

export const UNIAUTH_ATTRIBUTION = {
  packageName: packageMetadata.name,
  displayName,
  author: packageMetadata.author.name,
  copyright: `Copyright (c) 2026 ${packageMetadata.author.name}`,
  license: displayLicense,
  notice: `This product uses ${packageMetadata.name}.`,
  repositoryUrl: normalizeRepositoryUrl(packageMetadata.repository.url),
  contactEmail: packageMetadata.author.email,
} as const satisfies UniAuthAttributionDetails

export function getUniAuthAttributionNotice(options: UniAuthAttributionNoticeOptions = {}): string {
  const productName = options.productName?.trim()
  const subject = productName ? `${productName} uses` : 'This product uses'
  const parts = [`${subject} ${UNIAUTH_ATTRIBUTION.packageName}.`, UNIAUTH_ATTRIBUTION.copyright]

  if (options.includeLicense ?? true) {
    parts.push(`License: ${UNIAUTH_ATTRIBUTION.license}.`)
  }

  if (options.includeContact ?? true) {
    parts.push(`Licensing contact: ${UNIAUTH_ATTRIBUTION.contactEmail}.`)
  }

  return parts.join(' ')
}

/** @deprecated Use `UniAuthAttributionDetails` instead. */
export type UniauthAttributionDetails = UniAuthAttributionDetails

/** @deprecated Use `UniAuthAttributionNoticeOptions` instead. */
export type UniauthAttributionNoticeOptions = UniAuthAttributionNoticeOptions

/** @deprecated Use `getUniAuthAttributionNotice` instead. */
export const getUniauthAttributionNotice: typeof getUniAuthAttributionNotice =
  getUniAuthAttributionNotice
