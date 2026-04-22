import { createRequire } from 'node:module'
import { describe, expect, it } from 'vitest'

interface PackageMetadata {
  readonly name: string
  readonly license: string
  readonly author: {
    readonly name: string
    readonly email: string
  }
}

interface CoreExports {
  readonly DefaultAuthService: unknown
  readonly EMAIL_OTP_PROVIDER_ID: string
  readonly OtpChannel: { readonly Email: string; readonly Phone: string }
  readonly PHONE_OTP_PROVIDER_ID: string
  readonly UniAuthError: new (
    code: string,
    message: string,
    details?: Record<string, unknown>,
  ) => Error
  readonly UniAuthErrorCode: { readonly InvalidInput: string }
  readonly UNIAUTH_ATTRIBUTION: AttributionExports
  readonly getUniAuthAttributionNotice: (options?: {
    readonly productName?: string
    readonly includeLicense?: boolean
    readonly includeContact?: boolean
  }) => string
  readonly getUniauthAttributionNotice: (options?: {
    readonly productName?: string
    readonly includeLicense?: boolean
    readonly includeContact?: boolean
  }) => string
  readonly isUniAuthError: (error: unknown) => boolean
  readonly isUniauthError: (error: unknown) => boolean
  readonly UniauthError: new (
    code: string,
    message: string,
    details?: Record<string, unknown>,
  ) => Error
  readonly UniauthErrorCode: { readonly InvalidInput: string }
}

interface TestingExports {
  readonly createInMemoryAuthKit: unknown
  readonly InMemoryEmailSender: unknown
  readonly InMemorySmsSender: unknown
  readonly StaticAuthProvider: unknown
}

interface AttributionExports {
  readonly contactEmail: string
  readonly license: string
  readonly packageName: string
}

function formatPackageLicenseName(license: string): string {
  return license
    .replace(/^PolyForm-/, 'PolyForm ')
    .replace(/-(\d+\.\d+\.\d+)$/, ' License $1')
    .replaceAll('-', ' ')
}

const require = createRequire(import.meta.url)
const packageMetadata = require('../package.json') as PackageMetadata
const packageLicense = formatPackageLicenseName(packageMetadata.license)

describe('package exports', () => {
  it('loads the root entry point without mutating process environment', async () => {
    const before = { ...process.env }

    await import('../dist')

    expect(process.env).toEqual(before)
  })

  it('loads the public ESM entry points', async () => {
    const core = await import('../dist')
    const testing = await import('../dist/testing')

    expect(core.DefaultAuthService).toBeTypeOf('function')
    expect(core.EMAIL_OTP_PROVIDER_ID).toBe('email-otp')
    expect(core.OtpChannel.Phone).toBe('phone')
    expect(core.PHONE_OTP_PROVIDER_ID).toBe('phone-otp')
    expect(core.UniAuthError).toBeTypeOf('function')
    expect(core.UniAuthErrorCode.InvalidInput).toBe('invalid_input')
    expect(
      core.isUniAuthError(new core.UniAuthError(core.UniAuthErrorCode.InvalidInput, 'x')),
    ).toBe(true)
    expect(core.createDefaultAuthPolicy).toBeTypeOf('function')
    expect(core.UNIAUTH_ATTRIBUTION).toBeTypeOf('object')
    expect(core.getUniAuthAttributionNotice).toBeTypeOf('function')
    expect(core.getUniauthAttributionNotice).toBe(core.getUniAuthAttributionNotice)
    expect(core.UNIAUTH_ATTRIBUTION.license).toBe(packageLicense)
    expect(core.getUniAuthAttributionNotice({ productName: 'Smoke App' })).toContain(
      `Smoke App uses ${packageMetadata.name}.`,
    )
    expect(testing.createInMemoryAuthKit).toBeTypeOf('function')
    expect(testing.InMemoryEmailSender).toBeTypeOf('function')
    expect(testing.InMemorySmsSender).toBeTypeOf('function')
    expect(testing.StaticAuthProvider).toBeTypeOf('function')
  })

  it('loads the public CommonJS entry points', async () => {
    const core = require('../dist/index.cjs') as CoreExports
    const testing = require('../dist/testing/index.cjs') as TestingExports

    expect(core.DefaultAuthService).toBeTypeOf('function')
    expect(core.EMAIL_OTP_PROVIDER_ID).toBe('email-otp')
    expect(core.OtpChannel).toMatchObject({ Email: 'email', Phone: 'phone' })
    expect(core.PHONE_OTP_PROVIDER_ID).toBe('phone-otp')
    expect(core.UniAuthError).toBeTypeOf('function')
    expect(core.UniauthError).toBe(core.UniAuthError)
    expect(core.UniauthErrorCode).toBe(core.UniAuthErrorCode)
    expect(core.isUniauthError).toBe(core.isUniAuthError)
    expect(core.UNIAUTH_ATTRIBUTION).toBeTypeOf('object')
    expect(core.getUniAuthAttributionNotice).toBeTypeOf('function')
    expect(core.UNIAUTH_ATTRIBUTION).toMatchObject({
      contactEmail: packageMetadata.author.email,
      license: packageLicense,
      packageName: packageMetadata.name,
    })
    expect(core.getUniAuthAttributionNotice({ includeContact: false })).not.toContain(
      'Licensing contact',
    )
    expect(testing.createInMemoryAuthKit).toBeTypeOf('function')
    expect(testing.InMemoryEmailSender).toBeTypeOf('function')
    expect(testing.InMemorySmsSender).toBeTypeOf('function')
  })
})
