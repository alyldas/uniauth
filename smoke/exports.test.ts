import { readFile } from 'node:fs/promises'
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
    const bridges = await import('../dist/bridges')
    const contracts = await import('../dist/contracts')
    const core = await import('../dist')
    const postgres = await import('../dist/postgres')
    const testing = await import('../dist/testing')

    expect(Object.keys(contracts)).toEqual([])
    expect(bridges.mapAuthJsOAuthToAssertion).toBeTypeOf('function')
    expect(bridges.mapBetterAuthOAuthToAssertion).toBeTypeOf('function')
    expect(core.AuditEventType.SignIn).toBe('auth.sign_in')
    expect(core.AuditEventType.VerificationCancelled).toBe('auth.verification_cancelled')
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
    expect(core.RateLimitAction.OtpResend).toBe('otp:resend')
    expect(core.RateLimitAction.MagicLinkResend).toBe('magic-link:resend')
    expect(core.RateLimitAction.PasswordRecoveryResend).toBe('password-recovery:resend')
    expect(core.rateLimitKey).toBeTypeOf('function')
    expect(core.TELEGRAM_MINI_APP_PROVIDER_ID).toBe('telegram-mini-app')
    expect(core.UniAuthError).toBeTypeOf('function')
    expect(core.UniAuthErrorCode.InvalidCredentials).toBe('invalid_credentials')
    expect(core.UniAuthErrorCode.InvalidInput).toBe('invalid_input')
    expect(core.UniAuthErrorCode.RateLimited).toBe('rate_limited')
    expect(
      core.isUniAuthError(new core.UniAuthError(core.UniAuthErrorCode.InvalidInput, 'x')),
    ).toBe(true)
    expect(core.createDefaultAuthPolicy).toBeTypeOf('function')
    expect(core.createAuthNormalizer).toBeTypeOf('function')
    expect(core.createHmacSecretHasher).toBeTypeOf('function')
    expect(core.createScryptSecretHasher).toBeTypeOf('function')
    expect(core.getRateLimitedErrorDetails).toBeTypeOf('function')
    expect(core.isRateLimitedErrorDetails).toBeTypeOf('function')
    expect(core.DefaultAuthService.prototype.getUser).toBeTypeOf('function')
    expect(core.DefaultAuthService.prototype.getUserCredentials).toBeTypeOf('function')
    expect(core.DefaultAuthService.prototype.getAccountInspectionSnapshot).toBeTypeOf('function')
    expect(core.DefaultAuthService.prototype.getAccountSecuritySnapshot).toBeTypeOf('function')
    expect(core.DefaultAuthService.prototype.getAuditEventPage).toBeTypeOf('function')
    expect(core.DefaultAuthService.prototype.cancelVerification).toBeTypeOf('function')
    expect(core.DefaultAuthService.prototype.cancelOtpChallenge).toBeTypeOf('function')
    expect(core.DefaultAuthService.prototype.cancelEmailMagicLinkSignIn).toBeTypeOf('function')
    expect(core.DefaultAuthService.prototype.cancelEmailPasswordRecovery).toBeTypeOf('function')
    expect(core.DefaultAuthService.prototype.getVerificationResendWindow).toBeTypeOf('function')
    expect(core.DefaultAuthService.prototype.resendOtpChallenge).toBeTypeOf('function')
    expect(core.DefaultAuthService.prototype.resendEmailMagicLinkSignIn).toBeTypeOf('function')
    expect(core.DefaultAuthService.prototype.resendEmailPasswordRecovery).toBeTypeOf('function')
    expect(core.DefaultAuthService.prototype.resolveSessionContext).toBeTypeOf('function')
    expect(core.DefaultAuthService.prototype.getVerification).toBeTypeOf('function')
    expect(core.DefaultAuthService.prototype.revokeUserSessions).toBeTypeOf('function')
    expect(core.DefaultAuthService.prototype.getUserSessions).toBeTypeOf('function')
    expect(core.DefaultAuthService.prototype.touchSession).toBeTypeOf('function')
    expect(core.toAccountInspectionSnapshot).toBeTypeOf('function')
    expect(core.toAccountSecuritySnapshot).toBeTypeOf('function')
    expect(core.toAuditEventView).toBeTypeOf('function')
    expect(core.toAuditEventCursor).toBeTypeOf('function')
    expect(core.toAccountSecurityCredentialView).toBeTypeOf('function')
    expect(core.toVerificationResendWindow).toBeTypeOf('function')
    expect(core.toVerificationStatusView).toBeTypeOf('function')
    expect(core.createMaxWebAppProvider).toBeTypeOf('function')
    expect(core.createOAuthOidcProvider).toBeTypeOf('function')
    expect(core.createOAuthOidcTokenRecord).toBeTypeOf('function')
    expect(core.createTelegramMiniAppProvider).toBeTypeOf('function')
    expect(core.compatibilityAuthNormalizer).toBeTypeOf('object')
    expect(core.mapOAuthOidcProfileToAssertion).toBeTypeOf('function')
    expect(core.OAuthOidcTokenBindingKind.CallbackState).toBe('callback-state')
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
    expect(postgres.POSTGRES_AUTH_SCHEMA_SQL).toContain('create table if not exists uniauth_users')
    expect(postgres.applyPostgresAuthSchema).toBeTypeOf('function')
    expect(postgres.createPostgresAuthStore).toBeTypeOf('function')
    expect(testing.createInMemoryAuthKit).toBeTypeOf('function')
    expect(testing.InMemoryEmailSender).toBeTypeOf('function')
    expect(testing.InMemoryPasswordHasher).toBeTypeOf('function')
    expect(testing.InMemoryRateLimiter).toBeTypeOf('function')
    expect(testing.InMemorySmsSender).toBeTypeOf('function')
    expect(testing.StaticAuthProvider).toBeTypeOf('function')
  })

  it('keeps testing package declarations aligned with the stable public surface', async () => {
    const contractsDeclarations = await readFile(
      new URL('../dist/contracts.d.ts', import.meta.url),
      'utf8',
    )
    const contractsRuntimeDeclarations = await readFile(
      new URL('../dist/contracts/runtime.d.ts', import.meta.url),
      'utf8',
    )
    const testingKitDeclarations = await readFile(
      new URL('../dist/testing/in-memory/kit.d.ts', import.meta.url),
      'utf8',
    )

    expect(contractsDeclarations).toContain('AuthServiceInfrastructure')
    expect(contractsRuntimeDeclarations).toContain('export interface AuthNormalizer')
    expect(contractsRuntimeDeclarations).toContain('export interface SecretHasher')
    expect(testingKitDeclarations).not.toContain('export interface InMemoryAuthKit')
    expect(testingKitDeclarations).toContain('export interface CreateInMemoryAuthKitOptions')
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
    for (const privateProviderSubpath of [
      `${packageMetadata.name}/bridges/authjs.js`,
      `${packageMetadata.name}/bridges/better-auth.js`,
      `${packageMetadata.name}/contracts/runtime.js`,
      `${packageMetadata.name}/providers/messenger.js`,
      `${packageMetadata.name}/providers/oauth-oidc.js`,
      `${packageMetadata.name}/postgres/store.js`,
    ]) {
      const result = spawnSync(
        process.execPath,
        [
          '--input-type=module',
          '--eval',
          `await import(${JSON.stringify(privateProviderSubpath)})`,
        ],
        {
          cwd: process.cwd(),
          encoding: 'utf8',
        },
      )

      expect(result.status).not.toBe(0)
      expect(result.stderr).toContain('ERR_PACKAGE_PATH_NOT_EXPORTED')
    }
  })
})
