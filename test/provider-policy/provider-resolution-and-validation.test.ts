import { describe, expect, it } from 'vitest'
import { UniAuthErrorCode, type ProviderIdentityAssertion, createAuthService } from '../../src'
import { InMemoryAuthStore, StaticAuthProvider, createInMemoryAuthKit } from '../../src/testing'
import { assertion, now } from '../helpers.js'

describe('provider resolution and assertion validation failures', () => {
  it('covers provider resolution and assertion validation failures', async () => {
    const noRegistryService = createAuthService({ repos: new InMemoryAuthStore() })

    expect(
      await noRegistryService
        .signIn({ provider: 'missing', finishInput: {}, now })
        .catch((caught: unknown) => caught),
    ).toMatchObject({
      code: UniAuthErrorCode.ProviderNotFound,
    })
    expect(
      await noRegistryService.signIn({ now }).catch((caught: unknown) => caught),
    ).toMatchObject({
      code: UniAuthErrorCode.InvalidInput,
    })
    expect(
      await noRegistryService
        .signIn({
          assertion: assertion({ provider: '   ', providerUserId: 'user' }),
          now,
        })
        .catch((caught: unknown) => caught),
    ).toMatchObject({ code: UniAuthErrorCode.InvalidInput })
    expect(
      await noRegistryService
        .signIn({
          assertion: assertion({ provider: 'oauth', providerUserId: 'user\u0000a' }),
          now,
        })
        .catch((caught: unknown) => caught),
    ).toMatchObject({ code: UniAuthErrorCode.InvalidInput })
    expect(
      await noRegistryService
        .signIn({
          assertion: {
            providerUserId: 'user',
          } as Partial<ProviderIdentityAssertion> as ProviderIdentityAssertion,
          now,
        })
        .catch((caught: unknown) => caught),
    ).toMatchObject({ code: UniAuthErrorCode.InvalidInput })
    expect(
      await noRegistryService
        .signIn({
          assertion: {
            provider: 'email',
          } as Partial<ProviderIdentityAssertion> as ProviderIdentityAssertion,
          now,
        })
        .catch((caught: unknown) => caught),
    ).toMatchObject({ code: UniAuthErrorCode.InvalidInput })
    expect(
      await noRegistryService
        .signIn({
          assertion: {
            provider: 123,
            providerUserId: 'user',
          } as unknown as ProviderIdentityAssertion,
          now,
        })
        .catch((caught: unknown) => caught),
    ).toMatchObject({ code: UniAuthErrorCode.InvalidInput })
    expect(
      await noRegistryService
        .signIn({
          assertion: {
            provider: 'email',
            providerUserId: 'user',
            email: 123,
          } as unknown as ProviderIdentityAssertion,
          now,
        })
        .catch((caught: unknown) => caught),
    ).toMatchObject({ code: UniAuthErrorCode.InvalidInput })
    expect(
      await noRegistryService
        .signIn({
          assertion: assertion({
            provider: 'oauth',
            providerUserId: 'invalid-trust',
            trust: {
              level: 'unsupported' as 'trusted',
            },
          }),
          now,
        })
        .catch((caught: unknown) => caught),
    ).toMatchObject({ code: UniAuthErrorCode.InvalidInput })
    expect(
      await noRegistryService
        .signIn({
          assertion: {
            provider: 'oauth',
            providerUserId: 'invalid-trust-level-type',
            trust: {
              level: 1,
            },
          } as unknown as ProviderIdentityAssertion,
          now,
        })
        .catch((caught: unknown) => caught),
    ).toMatchObject({ code: UniAuthErrorCode.InvalidInput })
    expect(
      await noRegistryService
        .signIn({
          assertion: {
            provider: 'oauth',
            providerUserId: 'invalid-trust-signals-type',
            trust: {
              level: 'trusted',
              signals: 'not-an-array',
            },
          } as unknown as ProviderIdentityAssertion,
          now,
        })
        .catch((caught: unknown) => caught),
    ).toMatchObject({ code: UniAuthErrorCode.InvalidInput })
    expect(
      await noRegistryService
        .signIn({
          assertion: {
            provider: 'oauth',
            providerUserId: 'invalid-trust-type',
            trust: {
              level: 'trusted',
              signals: [123],
            },
          } as unknown as ProviderIdentityAssertion,
          now,
        })
        .catch((caught: unknown) => caught),
    ).toMatchObject({ code: UniAuthErrorCode.InvalidInput })
    expect(
      await noRegistryService
        .signIn({
          assertion: {
            provider: 'oauth',
            providerUserId: 'invalid-assertion-metadata',
            metadata: ['not-a-record'],
          } as unknown as ProviderIdentityAssertion,
          now,
        })
        .catch((caught: unknown) => caught),
    ).toMatchObject({ code: UniAuthErrorCode.InvalidInput })
    expect(
      await noRegistryService
        .signIn({
          assertion: {
            provider: 'oauth',
            providerUserId: 'invalid-trust-metadata',
            trust: {
              level: 'trusted',
              metadata: ['not-a-record'],
            },
          } as unknown as ProviderIdentityAssertion,
          now,
        })
        .catch((caught: unknown) => caught),
    ).toMatchObject({ code: UniAuthErrorCode.InvalidInput })

    const nullPrototypeMetadata = Object.assign(Object.create(null) as Record<string, unknown>, {
      source: 'provider',
    })

    await expect(
      noRegistryService.signIn({
        assertion: assertion({
          provider: 'oauth',
          providerUserId: 'plain-metadata',
          metadata: { source: 'assertion' },
          trust: {
            level: 'trusted',
            metadata: nullPrototypeMetadata,
          },
        }),
        now,
      }),
    ).resolves.toMatchObject({
      identity: {
        metadata: { source: 'assertion' },
      },
    })

    const { providerRegistry, service } = createInMemoryAuthKit()
    providerRegistry.register(
      new StaticAuthProvider(' oidc ', {
        providerUserId: 'provider-user-1',
        email: 'person@example.com',
        emailVerified: true,
      }),
    )

    await expect(
      service.signIn({
        provider: ' oidc ',
        finishInput: {},
        now,
      }),
    ).resolves.toMatchObject({
      identity: {
        provider: 'oidc',
        providerUserId: 'provider-user-1',
      },
    })
    await expect(
      service.signIn({
        provider: '   ',
        finishInput: {},
        now,
      }),
    ).rejects.toMatchObject({
      code: UniAuthErrorCode.InvalidInput,
    })
    await expect(
      service.signIn({
        // @ts-expect-error runtime validation for untyped callers
        provider: 123,
        finishInput: {},
        now,
      }),
    ).rejects.toMatchObject({
      code: UniAuthErrorCode.InvalidInput,
    })
  })
})
