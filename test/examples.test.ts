import { describe, expect, it } from 'vitest'
import { UniAuthErrorCode } from '../src'
import { readBearerToken, readCookieHeaderToken } from '../examples/shared/http.js'
import { finishOidcCallbackForExample } from '../examples/oauth-oidc/index.js'

describe('example transport helpers', () => {
  it('rejects ambiguous bearer headers and malformed cookie encoding', () => {
    expect(readBearerToken('Bearer token')).toBe('token')
    expect(readBearerToken('Bearer token extra')).toBeUndefined()
    expect(readBearerToken('Basic token')).toBeUndefined()
    expect(readCookieHeaderToken('session=%', 'session')).toBeUndefined()
    expect(readCookieHeaderToken('session=abc%20123', 'session')).toBe('abc 123')
  })

  it('validates OAuth callback query and cookie values before provider finish', async () => {
    await expect(
      finishOidcCallbackForExample({
        query: {
          code: 'demo-authorization-code',
          state: 'state-123',
        },
        cookies: {
          oidcState: 'state-123',
          oidcCodeVerifier: '   ',
          oidcRedirectUri: 'https://app.example.test/auth/callback',
        },
      }),
    ).rejects.toMatchObject({
      code: UniAuthErrorCode.InvalidInput,
    })
  })
})
