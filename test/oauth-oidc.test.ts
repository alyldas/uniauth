import { describe, expect, it } from 'vitest'
import {
  AuditEventType,
  OAuthOidcTokenBindingKind,
  UniAuthErrorCode,
  createOAuthOidcTokenRecord,
  createOAuthOidcProvider,
  mapOAuthOidcProfileToAssertion,
  type OAuthOidcAuthorizationCodeExchangeInput,
  type OAuthOidcClient,
  type OAuthOidcFetchProfileInput,
  type OAuthOidcProfile,
  type OAuthOidcTokenSet,
} from '../src'
import { createInMemoryAuthKit } from '../src/testing'
import { now } from './helpers.js'

class RecordingOAuthOidcClient implements OAuthOidcClient {
  exchangeInput?: OAuthOidcAuthorizationCodeExchangeInput
  fetchProfileInput?: OAuthOidcFetchProfileInput

  constructor(
    private readonly tokens: OAuthOidcTokenSet,
    private readonly profile: OAuthOidcProfile,
  ) {}

  async exchangeCode(input: OAuthOidcAuthorizationCodeExchangeInput): Promise<OAuthOidcTokenSet> {
    this.exchangeInput = input

    return this.tokens
  }

  async fetchProfile(input: OAuthOidcFetchProfileInput): Promise<OAuthOidcProfile> {
    this.fetchProfileInput = input

    return this.profile
  }
}

async function catchError(operation: () => unknown | Promise<unknown>): Promise<unknown> {
  try {
    await operation()
  } catch (error) {
    return error
  }

  throw new Error('Expected operation to fail.')
}

async function expectInvalid(operation: () => unknown | Promise<unknown>): Promise<void> {
  const error = await catchError(operation)

  expect(error).toMatchObject({
    code: UniAuthErrorCode.InvalidInput,
  })
}

describe('OAuth/OIDC provider contract', () => {
  it('exchanges authorization codes, fetches profiles, and maps assertions', async () => {
    const client = new RecordingOAuthOidcClient(
      {
        accessToken: ' access-token ',
        refreshToken: ' refresh-token ',
        tokenType: 'Bearer',
        scopes: ['openid', 'email'],
      },
      {
        subject: ' subject-123 ',
        email: ' Person@Example.COM ',
        emailVerified: true,
        displayName: ' OAuth User ',
        issuer: ' https://issuer.example ',
        preferredUsername: ' oauth-user ',
        pictureUrl: ' https://example.com/avatar.png ',
        locale: ' en ',
        metadata: {
          tenant: 'tenant-1',
        },
      },
    )
    const provider = createOAuthOidcProvider({
      providerId: 'example-oauth',
      client,
    })

    const assertion = await provider.finish({
      code: ' code-1 ',
      state: ' state-1 ',
      payload: {
        redirectUri: ' https://app.example/callback ',
        codeVerifier: ' verifier-1 ',
        metadata: {
          requestId: 'request-1',
        },
      },
    })

    expect(provider.id).toBe('example-oauth')
    expect(client.exchangeInput).toEqual({
      code: 'code-1',
      state: 'state-1',
      redirectUri: 'https://app.example/callback',
      codeVerifier: 'verifier-1',
      metadata: {
        requestId: 'request-1',
      },
    })
    expect(client.fetchProfileInput).toEqual({
      tokens: {
        accessToken: 'access-token',
        refreshToken: 'refresh-token',
        tokenType: 'Bearer',
        scopes: ['openid', 'email'],
      },
      state: 'state-1',
      metadata: {
        requestId: 'request-1',
      },
    })
    expect(assertion).toEqual({
      provider: 'example-oauth',
      providerUserId: 'subject-123',
      email: 'Person@Example.COM',
      emailVerified: true,
      displayName: 'OAuth User',
      metadata: {
        issuer: 'https://issuer.example',
        preferredUsername: 'oauth-user',
        pictureUrl: 'https://example.com/avatar.png',
        locale: 'en',
        tenant: 'tenant-1',
      },
    })
    expect(assertion.metadata).not.toHaveProperty('accessToken')
    expect(assertion.metadata).not.toHaveProperty('refreshToken')
    expect(assertion.metadata).not.toHaveProperty('idToken')
  })

  it('uses OAuth/OIDC providers through the existing sign-in pipeline', async () => {
    const kit = createInMemoryAuthKit()
    const provider = createOAuthOidcProvider({
      providerId: 'oidc',
      client: new RecordingOAuthOidcClient(
        { idToken: 'id-token' },
        {
          subject: 'oidc-user',
          email: 'OIDC@Example.COM',
          emailVerified: true,
        },
      ),
    })

    kit.providerRegistry.register(provider)

    const result = await kit.service.signIn({
      provider: 'oidc',
      finishInput: {
        payload: {
          code: 'oidc-code',
        },
      },
      now,
    })

    expect(result.identity.provider).toBe('oidc')
    expect(result.identity.providerUserId).toBe('oidc-user')
    expect(result.identity.email).toBe('oidc@example.com')
    expect(result.identity.emailVerified).toBe(true)
    expect(kit.store.listAuditEvents().map((event) => event.type)).toContain(AuditEventType.SignIn)
  })

  it('omits blank optional callback fields and falls back to payload code', async () => {
    const client = new RecordingOAuthOidcClient(
      { accessToken: 'token' },
      {
        subject: 'blank-optionals-user',
      },
    )
    const provider = createOAuthOidcProvider({
      providerId: 'blank-optionals',
      client,
    })

    await provider.finish({
      code: '   ',
      state: '   ',
      metadata: {
        requestId: 'fallback-request',
      },
      payload: {
        code: ' payload-code ',
        redirectUri: '   ',
        codeVerifier: '   ',
      },
    })

    expect(client.exchangeInput).toEqual({
      code: 'payload-code',
      metadata: {
        requestId: 'fallback-request',
      },
    })
  })

  it('rejects malformed OAuth/OIDC finish metadata instead of falling back', async () => {
    const client = new RecordingOAuthOidcClient(
      { accessToken: 'token' },
      {
        subject: 'metadata-user',
      },
    )
    const provider = createOAuthOidcProvider({
      providerId: 'metadata-provider',
      client,
    })

    await expect(
      catchError(() =>
        provider.finish({
          code: 'code',
          metadata: {
            requestId: 'fallback-request',
          },
          payload: {
            metadata: 'not-metadata',
          },
        }),
      ),
    ).resolves.toMatchObject({
      code: UniAuthErrorCode.InvalidInput,
      message: 'OAuth/OIDC finish metadata must be a plain object.',
    })
    expect(client.exchangeInput).toBeUndefined()

    await expect(
      catchError(() =>
        provider.finish({
          code: 'code',
          metadata: new Date() as unknown as Record<string, unknown>,
        }),
      ),
    ).resolves.toMatchObject({
      code: UniAuthErrorCode.InvalidInput,
      message: 'OAuth/OIDC finish metadata must be a plain object.',
    })
  })

  it('supports explicit profile mappers without exposing token storage in core', async () => {
    const provider = createOAuthOidcProvider({
      providerId: 'custom-oauth',
      client: new RecordingOAuthOidcClient(
        { accessToken: 'token' },
        {
          subject: 'profile-subject',
          preferredUsername: 'custom-name',
        },
      ),
      mapProfile: ({ provider, profile, exchangeInput }) => ({
        provider,
        providerUserId: `${profile.subject}:${exchangeInput.code}`,
        displayName: profile.preferredUsername ?? 'fallback-name',
        metadata: {
          mapped: true,
        },
      }),
    })

    const assertion = await provider.finish({ code: 'mapper-code' })

    expect(assertion).toEqual({
      provider: 'custom-oauth',
      providerUserId: 'profile-subject:mapper-code',
      displayName: 'custom-name',
      metadata: {
        mapped: true,
      },
    })
  })

  it('maps profiles directly for adapter tests', () => {
    expect(
      mapOAuthOidcProfileToAssertion({
        provider: 'direct',
        profile: {
          subject: 'direct-subject',
          phone: ' +1 555 123 4567 ',
          phoneVerified: true,
          displayName: ' Direct User ',
        },
        finishInput: {},
        exchangeInput: {
          code: 'code',
        },
      }),
    ).toEqual({
      provider: 'direct',
      providerUserId: 'direct-subject',
      phone: '+1 555 123 4567',
      phoneVerified: true,
      displayName: 'Direct User',
    })
  })

  it('rejects OAuth/OIDC profile metadata that is not a plain object', async () => {
    await expect(
      catchError(() =>
        mapOAuthOidcProfileToAssertion({
          provider: 'direct',
          profile: {
            subject: 'direct-subject',
            metadata: ['tenant-1'] as unknown as Record<string, unknown>,
          },
          finishInput: {},
          exchangeInput: {
            code: 'code',
          },
        }),
      ),
    ).resolves.toMatchObject({
      code: UniAuthErrorCode.InvalidInput,
      message: 'OAuth/OIDC profile metadata must be a plain object.',
    })
  })

  it('creates normalized token records for application-owned persistence', () => {
    const metadata = Object.assign(Object.create(null) as Record<string, unknown>, {
      tenantId: 'tenant-1',
    })

    expect(
      createOAuthOidcTokenRecord({
        provider: ' example-oauth ',
        providerUserId: ' subject-123 ',
        binding: {
          kind: OAuthOidcTokenBindingKind.CallbackState,
          value: ' state-123 ',
        },
        tokens: {
          accessToken: ' access-token ',
          refreshToken: ' refresh-token ',
          idToken: ' id-token ',
          tokenType: ' Bearer ',
          expiresAt: now,
          scopes: ['openid', ' email ', 'openid', '   '],
        },
        metadata,
      }),
    ).toEqual({
      provider: 'example-oauth',
      providerUserId: 'subject-123',
      binding: {
        kind: OAuthOidcTokenBindingKind.CallbackState,
        value: 'state-123',
      },
      accessToken: 'access-token',
      refreshToken: 'refresh-token',
      idToken: 'id-token',
      tokenType: 'Bearer',
      expiresAt: now,
      scopes: ['openid', 'email'],
      metadata: {
        tenantId: 'tenant-1',
      },
    })
  })

  it('supports refresh-token-only records and drops blank optional persistence fields', () => {
    expect(
      createOAuthOidcTokenRecord({
        provider: 'example-oauth',
        providerUserId: 'subject-456',
        binding: {
          kind: OAuthOidcTokenBindingKind.User,
          value: 'user-456',
        },
        tokens: {
          refreshToken: ' refresh-token ',
          scopes: ['   '],
        },
      }),
    ).toEqual({
      provider: 'example-oauth',
      providerUserId: 'subject-456',
      binding: {
        kind: OAuthOidcTokenBindingKind.User,
        value: 'user-456',
      },
      refreshToken: 'refresh-token',
    })
  })

  it('rejects incomplete OAuth/OIDC inputs', async () => {
    await expectInvalid(() =>
      createOAuthOidcProvider({
        providerId: '',
        client: new RecordingOAuthOidcClient({ accessToken: 'token' }, { subject: 'subject' }),
      }).finish({ code: 'code' }),
    )

    await expectInvalid(() =>
      createOAuthOidcProvider({
        providerId: 'oauth',
        client: new RecordingOAuthOidcClient({ accessToken: 'token' }, { subject: 'subject' }),
      }).finish({}),
    )

    await expectInvalid(() =>
      createOAuthOidcProvider({
        providerId: 'oauth',
        client: new RecordingOAuthOidcClient({}, { subject: 'subject' }),
      }).finish({ code: 'code' }),
    )

    await expectInvalid(() =>
      createOAuthOidcProvider({
        providerId: 'oauth',
        client: new RecordingOAuthOidcClient(undefined as unknown as OAuthOidcTokenSet, {
          subject: 'subject',
        }),
      }).finish({ code: 'code' }),
    )
    await expectInvalid(() =>
      createOAuthOidcProvider({
        providerId: 'oauth',
        client: new RecordingOAuthOidcClient(
          { accessToken: 'token', expiresAt: new Date('invalid') },
          { subject: 'subject' },
        ),
      }).finish({ code: 'code' }),
    )
    await expectInvalid(() =>
      createOAuthOidcProvider({
        providerId: 'oauth',
        client: new RecordingOAuthOidcClient(
          { accessToken: 'token', scopes: ['openid', 42] as unknown as readonly string[] },
          { subject: 'subject' },
        ),
      }).finish({ code: 'code' }),
    )

    await expectInvalid(() =>
      createOAuthOidcProvider({
        providerId: 'oauth',
        client: new RecordingOAuthOidcClient({ accessToken: 'token' }, { subject: '   ' }),
      }).finish({ code: 'code' }),
    )

    await expectInvalid(() =>
      createOAuthOidcTokenRecord({
        provider: 'oauth',
        providerUserId: 'subject',
        binding: {
          kind: OAuthOidcTokenBindingKind.Session,
          value: 'session-1',
        },
        tokens: {},
      }),
    )
    await expectInvalid(() =>
      createOAuthOidcTokenRecord({
        provider: 'oauth',
        providerUserId: 'subject',
        binding: {
          kind: '   ',
          value: 'session-1',
        },
        tokens: {
          refreshToken: 'refresh-token',
        },
      }),
    )
    await expectInvalid(() =>
      createOAuthOidcTokenRecord({
        provider: 'oauth',
        providerUserId: 'subject',
        binding: undefined as unknown as {
          kind: string
          value: string
        },
        tokens: {
          refreshToken: 'refresh-token',
        },
      }),
    )
    await expectInvalid(() =>
      createOAuthOidcTokenRecord({
        provider: 'oauth',
        providerUserId: 'subject',
        binding: {
          kind: OAuthOidcTokenBindingKind.User,
          value: 'user-1',
        },
        tokens: undefined as unknown as OAuthOidcTokenSet,
      }),
    )
    await expectInvalid(() =>
      createOAuthOidcTokenRecord({
        provider: 'oauth',
        providerUserId: 'subject',
        binding: {
          kind: OAuthOidcTokenBindingKind.User,
          value: 'user-1',
        },
        tokens: {
          refreshToken: 'refresh-token',
          expiresAt: new Date('invalid'),
        },
      }),
    )
    await expectInvalid(() =>
      createOAuthOidcTokenRecord({
        provider: 'oauth',
        providerUserId: 'subject',
        binding: {
          kind: OAuthOidcTokenBindingKind.User,
          value: 'user-1',
        },
        tokens: {
          refreshToken: 'refresh-token',
          scopes: ['openid', 42] as unknown as readonly string[],
        },
      }),
    )
    await expectInvalid(() =>
      createOAuthOidcTokenRecord({
        provider: 'oauth',
        providerUserId: 'subject',
        binding: {
          kind: OAuthOidcTokenBindingKind.User,
          value: 'user-1',
        },
        tokens: {
          refreshToken: 'refresh-token',
        },
        metadata: 'not-an-object' as unknown as Record<string, unknown>,
      }),
    )
    await expectInvalid(() =>
      createOAuthOidcTokenRecord({
        provider: 'oauth',
        providerUserId: 'subject',
        binding: {
          kind: OAuthOidcTokenBindingKind.User,
          value: 'user-1',
        },
        tokens: {
          refreshToken: 'refresh-token',
        },
        metadata: new Date() as unknown as Record<string, unknown>,
      }),
    )
  })
})
