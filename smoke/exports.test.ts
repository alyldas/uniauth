import { spawnSync } from 'node:child_process'
import { describe, expect, it } from 'vitest'
import packageJson from '../package.json'

interface PackageMetadata {
  readonly name: string
  readonly author: {
    readonly email: string
  }
}

const packageMetadata = packageJson as PackageMetadata

describe('package exports', () => {
  it('loads the root entry point without mutating process environment', async () => {
    const before = { ...process.env }

    await import('../dist')

    expect(process.env).toEqual(before)
  })

  it('loads the public ESM entry points', async () => {
    const core = await import('../dist')
    const testing = await import('../dist/testing')

    expect(core.AuditEventType.SignIn).toBe('auth.sign_in')
    expect(core.CredentialType.Password).toBe('password')
    expect(core.AuthPolicyAction.ChangePassword).toBe('changePassword')
    expect(core.DefaultAuthService).toBeTypeOf('function')
    expect(core.EMAIL_MAGIC_LINK_PROVIDER_ID).toBe('email-magic-link')
    expect(core.EMAIL_OTP_PROVIDER_ID).toBe('email-otp')
    expect(core.MAX_WEBAPP_PROVIDER_ID).toBe('max-webapp')
    expect(core.OtpChannel.Phone).toBe('phone')
    expect(core.PASSWORD_PROVIDER_ID).toBe('password')
    expect(core.PHONE_OTP_PROVIDER_ID).toBe('phone-otp')
    expect(core.RateLimitAction.ProviderSignIn).toBe('provider:sign-in')
    expect(core.TELEGRAM_MINI_APP_PROVIDER_ID).toBe('telegram-mini-app')
    expect(core.UniAuthError).toBeTypeOf('function')
    expect(core.UniAuthErrorCode.InvalidCredentials).toBe('invalid_credentials')
    expect(core.UniAuthErrorCode.InvalidInput).toBe('invalid_input')
    expect(core.UniAuthErrorCode.RateLimited).toBe('rate_limited')
    expect(
      core.isUniAuthError(new core.UniAuthError(core.UniAuthErrorCode.InvalidInput, 'x')),
    ).toBe(true)
    expect(core.createDefaultAuthPolicy).toBeTypeOf('function')
    expect(core.createHmacSecretHasher).toBeTypeOf('function')
    expect(core.createMaxWebAppProvider).toBeTypeOf('function')
    expect(core.createTelegramMiniAppProvider).toBeTypeOf('function')
    expect(core.validateSignedWebAppInitData).toBeTypeOf('function')
    expect(core.UNIAUTH_ATTRIBUTION).toBeTypeOf('object')
    expect(core.getUniAuthAttributionNotice).toBeTypeOf('function')
    expect(core.UNIAUTH_ATTRIBUTION).toMatchObject({
      contactEmail: packageMetadata.author.email,
      packageName: packageMetadata.name,
    })
    expect(core.getUniAuthAttributionNotice({ productName: 'Smoke App' })).toContain(
      `Smoke App uses ${packageMetadata.name}.`,
    )
    expect(testing.createInMemoryAuthKit).toBeTypeOf('function')
    expect(testing.InMemoryEmailSender).toBeTypeOf('function')
    expect(testing.InMemoryPasswordHasher).toBeTypeOf('function')
    expect(testing.InMemoryRateLimiter).toBeTypeOf('function')
    expect(testing.InMemorySmsSender).toBeTypeOf('function')
    expect(testing.StaticAuthProvider).toBeTypeOf('function')
  })

  it('keeps internal application helpers private', () => {
    const privateOptionalSubpath = `${packageMetadata.name}/application/optional.js`
    const result = spawnSync(
      process.execPath,
      ['--input-type=module', '--eval', `await import(${JSON.stringify(privateOptionalSubpath)})`],
      {
        cwd: process.cwd(),
        encoding: 'utf8',
      },
    )

    expect(result.status).not.toBe(0)
    expect(result.stderr).toContain('ERR_PACKAGE_PATH_NOT_EXPORTED')
  })

  it('keeps internal provider adapter modules private', () => {
    const privateProviderSubpath = `${packageMetadata.name}/providers/messenger.js`
    const result = spawnSync(
      process.execPath,
      ['--input-type=module', '--eval', `await import(${JSON.stringify(privateProviderSubpath)})`],
      {
        cwd: process.cwd(),
        encoding: 'utf8',
      },
    )

    expect(result.status).not.toBe(0)
    expect(result.stderr).toContain('ERR_PACKAGE_PATH_NOT_EXPORTED')
  })
})
