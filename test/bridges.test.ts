import { describe, expect, it } from 'vitest'
import { ProviderTrustLevel, UniAuthErrorCode } from '../src'
import { mapAuthJsOAuthToAssertion, mapBetterAuthOAuthToAssertion } from '../src/bridges'
import { createInMemoryAuthKit } from '../src/testing'
import { now } from './helpers.js'

async function catchError(operation: () => unknown | Promise<unknown>): Promise<unknown> {
  try {
    await operation()
  } catch (error) {
    return error
  }

  throw new Error('Expected operation to fail.')
}

describe('auth bridge helpers', () => {
  it('maps Auth.js oauth inputs into a UniAuth assertion without copying tokens', () => {
    const assertion = mapAuthJsOAuthToAssertion({
      providerId: 'google-workspace',
      account: {
        provider: 'google',
        providerAccountId: ' provider-user-1 ',
        type: 'oauth',
      },
      profile: {
        sub: 'provider-user-1',
        email: ' Person@Example.COM ',
        email_verified: 'true',
        phone_number: ' +1 555 000 1234 ',
        phone_number_verified: false,
        name: ' Person Example ',
        preferred_username: ' person ',
        picture: ' https://example.com/avatar.png ',
        locale: ' en ',
      },
      user: {
        image: ' https://example.com/fallback.png ',
      },
      trust: {
        level: ProviderTrustLevel.Trusted,
        signals: ['workspace-admin'],
      },
      metadata: {
        tenantId: 'tenant-1',
      },
    })

    expect(assertion).toEqual({
      provider: 'google-workspace',
      providerUserId: 'provider-user-1',
      email: 'Person@Example.COM',
      emailVerified: true,
      phone: '+1 555 000 1234',
      phoneVerified: false,
      displayName: 'Person Example',
      trust: {
        level: ProviderTrustLevel.Trusted,
        signals: ['workspace-admin'],
      },
      metadata: {
        frameworkProviderId: 'google',
        preferredUsername: 'person',
        pictureUrl: 'https://example.com/avatar.png',
        locale: 'en',
        tenantId: 'tenant-1',
      },
    })
    expect(assertion.metadata).not.toHaveProperty('accessToken')
    expect(assertion.metadata).not.toHaveProperty('refreshToken')
    expect(assertion.metadata).not.toHaveProperty('idToken')
  })

  it('rejects Auth.js non-oauth accounts and mismatched subjects', async () => {
    await expect(
      catchError(() =>
        mapAuthJsOAuthToAssertion({
          account: {
            provider: 'credentials',
            providerAccountId: 'user-1',
            type: 'credentials',
          },
        }),
      ),
    ).resolves.toMatchObject({
      code: UniAuthErrorCode.InvalidInput,
      message: 'Auth.js bridge only accepts oauth or oidc accounts.',
    })

    await expect(
      catchError(() =>
        mapAuthJsOAuthToAssertion({
          account: {
            provider: 'google',
            providerAccountId: 'user-1',
            type: 'oauth',
          },
          profile: {
            sub: 'user-2',
          },
        }),
      ),
    ).resolves.toMatchObject({
      code: UniAuthErrorCode.InvalidInput,
      message: 'Auth.js account providerAccountId and profile subject must match.',
    })

    await expect(
      catchError(() =>
        mapAuthJsOAuthToAssertion({
          account: {
            provider: 'google',
            providerAccountId: '   ',
          },
        }),
      ),
    ).resolves.toMatchObject({
      code: UniAuthErrorCode.InvalidInput,
      message: 'Auth.js account providerAccountId is required.',
    })
  })

  it('supports Auth.js fallback fields and keeps metadata empty when nothing safe is left', () => {
    expect(
      mapAuthJsOAuthToAssertion({
        account: {
          provider: 'github',
          providerAccountId: ' github-user-1 ',
          type: 'oidc',
        },
        profile: {
          id: 'github-user-1',
          email_verified: 'not-a-boolean',
          name: '   ',
          preferred_username: '   ',
          picture: '   ',
          locale: '   ',
        },
        user: {
          email: ' GitHubUser@Example.COM ',
          emailVerified: 'false',
          name: ' GitHub User ',
          image: ' https://example.com/github.png ',
        },
      }),
    ).toEqual({
      provider: 'github',
      providerUserId: 'github-user-1',
      email: 'GitHubUser@Example.COM',
      emailVerified: false,
      displayName: 'GitHub User',
      metadata: {
        pictureUrl: 'https://example.com/github.png',
      },
    })
  })

  it('returns a minimal Auth.js assertion when only the exact provider identity is available', () => {
    expect(
      mapAuthJsOAuthToAssertion({
        account: {
          provider: 'google',
          providerAccountId: 'google-user-1',
        },
      }),
    ).toEqual({
      provider: 'google',
      providerUserId: 'google-user-1',
    })
  })

  it('rejects Auth.js metadata that is not a plain object', async () => {
    await expect(
      catchError(() =>
        mapAuthJsOAuthToAssertion({
          account: {
            provider: 'google',
            providerAccountId: 'user-1',
          },
          metadata: ['tenant-1'] as unknown as Record<string, unknown>,
        }),
      ),
    ).resolves.toMatchObject({
      code: UniAuthErrorCode.InvalidInput,
      message: 'Bridge metadata must be a plain object.',
    })

    await expect(
      catchError(() =>
        mapAuthJsOAuthToAssertion({
          account: {
            provider: 'google',
            providerAccountId: 'user-1',
          },
          metadata: new Date() as unknown as Record<string, unknown>,
        }),
      ),
    ).resolves.toMatchObject({
      code: UniAuthErrorCode.InvalidInput,
      message: 'Bridge metadata must be a plain object.',
    })
  })

  it('accepts Auth.js metadata records without an object prototype', () => {
    const metadata = Object.assign(Object.create(null) as Record<string, unknown>, {
      tenantId: 'tenant-1',
    })

    expect(
      mapAuthJsOAuthToAssertion({
        account: {
          provider: 'google',
          providerAccountId: 'user-1',
        },
        metadata,
      }).metadata,
    ).toEqual({
      tenantId: 'tenant-1',
    })
  })

  it('maps Better Auth account or profile data without copying account tokens', () => {
    const assertion = mapBetterAuthOAuthToAssertion({
      providerId: 'discord-app',
      account: {
        providerId: 'discord',
        accountId: ' discord-user-1 ',
      },
      profile: {
        id: 'discord-user-1',
        email: ' Discord@Example.COM ',
        emailVerified: true,
        name: ' Discord User ',
        image: ' https://example.com/discord.png ',
      },
      user: {
        email: 'ignored@example.com',
        image: 'https://example.com/fallback.png',
      },
      metadata: {
        tenantId: 'tenant-2',
      },
    })

    expect(assertion).toEqual({
      provider: 'discord-app',
      providerUserId: 'discord-user-1',
      email: 'Discord@Example.COM',
      emailVerified: true,
      displayName: 'Discord User',
      metadata: {
        frameworkProviderId: 'discord',
        pictureUrl: 'https://example.com/discord.png',
        tenantId: 'tenant-2',
      },
    })
    expect(assertion.metadata).not.toHaveProperty('accessToken')
    expect(assertion.metadata).not.toHaveProperty('refreshToken')
    expect(assertion.metadata).not.toHaveProperty('idToken')
  })

  it('supports Better Auth profile-only mapping when the app chooses the provider id', () => {
    expect(
      mapBetterAuthOAuthToAssertion({
        providerId: 'github',
        profile: {
          id: 'github-user-1',
          name: ' GitHub User ',
          email: ' GitHub@Example.COM ',
          emailVerified: 'false',
        },
        trust: {
          level: ProviderTrustLevel.Neutral,
        },
      }),
    ).toEqual({
      provider: 'github',
      providerUserId: 'github-user-1',
      email: 'GitHub@Example.COM',
      emailVerified: false,
      displayName: 'GitHub User',
      trust: {
        level: ProviderTrustLevel.Neutral,
      },
    })
  })

  it('rejects Better Auth inputs without a stable provider id or with conflicting subjects', async () => {
    await expect(
      catchError(() =>
        mapBetterAuthOAuthToAssertion({
          profile: {
            id: 'user-1',
          },
        }),
      ),
    ).resolves.toMatchObject({
      code: UniAuthErrorCode.InvalidInput,
      message: 'Better Auth bridge providerId is required.',
    })

    await expect(
      catchError(() =>
        mapBetterAuthOAuthToAssertion({
          providerId: 'discord',
          account: {
            accountId: 'user-1',
          },
          profile: {
            id: 'user-2',
          },
        }),
      ),
    ).resolves.toMatchObject({
      code: UniAuthErrorCode.InvalidInput,
      message: 'Better Auth accountId and profile.id must match when both are provided.',
    })

    await expect(
      catchError(() =>
        mapBetterAuthOAuthToAssertion({
          providerId: 'discord',
          account: {
            providerId: 'discord',
          },
        }),
      ),
    ).resolves.toMatchObject({
      code: UniAuthErrorCode.InvalidInput,
      message: 'Better Auth accountId or profile.id is required.',
    })
  })

  it('returns a minimal Better Auth assertion when only the provider account record is available', () => {
    expect(
      mapBetterAuthOAuthToAssertion({
        account: {
          providerId: 'google',
          accountId: ' google-user-2 ',
        },
      }),
    ).toEqual({
      provider: 'google',
      providerUserId: 'google-user-2',
    })
  })

  it('rejects Better Auth metadata that is not a plain object', async () => {
    await expect(
      catchError(() =>
        mapBetterAuthOAuthToAssertion({
          account: {
            providerId: 'google',
            accountId: 'user-1',
          },
          metadata: ['tenant-1'] as unknown as Record<string, unknown>,
        }),
      ),
    ).resolves.toMatchObject({
      code: UniAuthErrorCode.InvalidInput,
      message: 'Bridge metadata must be a plain object.',
    })
  })

  it('feeds mapped framework assertions through the normal sign-in pipeline', async () => {
    const kit = createInMemoryAuthKit()

    const result = await kit.service.signIn({
      assertion: mapAuthJsOAuthToAssertion({
        account: {
          provider: 'authjs-google',
          providerAccountId: 'authjs-user-1',
          type: 'oauth',
        },
        profile: {
          sub: 'authjs-user-1',
          email: 'Bridge@Example.COM',
          email_verified: true,
          name: 'Bridge User',
        },
      }),
      now,
    })

    expect(result.identity.provider).toBe('authjs-google')
    expect(result.identity.providerUserId).toBe('authjs-user-1')
    expect(result.identity.email).toBe('bridge@example.com')
    expect(result.identity.emailVerified).toBe(true)
    expect(result.user.id).toBe(result.session.userId)
  })
})
