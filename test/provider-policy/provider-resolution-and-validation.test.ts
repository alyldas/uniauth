import { describe, expect, it } from 'vitest'
import { UniAuthErrorCode, type ProviderIdentityAssertion, createAuthService } from '../../src'
import { InMemoryAuthStore } from '../../src/testing'
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
  })
})
