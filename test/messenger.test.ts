import { createHmac } from 'node:crypto'
import { describe, expect, it } from 'vitest'
import {
  AuditEventType,
  MAX_WEBAPP_PROVIDER_ID,
  TELEGRAM_MINI_APP_PROVIDER_ID,
  UniAuthErrorCode,
  createMaxWebAppProvider,
  createTelegramMiniAppProvider,
  validateSignedWebAppInitData,
} from '../src'
import { createInMemoryAuthKit } from '../src/testing'
import { now } from './helpers.js'

const botToken = '123456:telegram-or-max-test-token'
const authDateSeconds = Math.floor(now.getTime() / 1000).toString()
const user = {
  id: 67890,
  first_name: 'Max',
  last_name: 'User',
  username: 'max_user',
  language_code: 'ru',
  photo_url: 'https://example.com/avatar.png',
}

function signInitData(fields: Readonly<Record<string, string>>, token = botToken): string {
  const dataCheckString = Object.entries(fields)
    .sort(([left], [right]) => (left < right ? -1 : left > right ? 1 : 0))
    .map(([key, value]) => `${key}=${value}`)
    .join('\n')
  const secretKey = createHmac('sha256', 'WebAppData').update(token).digest()
  const hash = createHmac('sha256', secretKey).update(dataCheckString).digest('hex')
  const params = new URLSearchParams(fields)

  params.set('hash', hash)

  return params.toString()
}

function validFields(overrides: Readonly<Record<string, string>> = {}): Record<string, string> {
  return {
    auth_date: authDateSeconds,
    query_id: 'query-1',
    start_param: 'launch',
    user: JSON.stringify(user),
    ...overrides,
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

describe('messenger WebApp providers', () => {
  it('validates signed WebApp init data with auth_date max age checks', () => {
    const initData = signInitData(validFields())
    const validated = validateSignedWebAppInitData({
      initData: `?${initData}`,
      botToken,
      now,
      maxAgeSeconds: 60,
    })

    expect(validated.authDate).toEqual(now)
    expect(validated.fields.query_id).toBe('query-1')
    expect(
      validateSignedWebAppInitData({
        initData: signInitData(
          validFields({ auth_date: Math.floor(Date.now() / 1000).toString() }),
        ),
        botToken,
        maxAgeSeconds: 60,
      }).authDate,
    ).toBeInstanceOf(Date)
  })

  it('maps Telegram Mini App init data into a provider assertion', async () => {
    const provider = createTelegramMiniAppProvider({
      botToken,
      clock: { now: () => now },
      maxAgeSeconds: 60,
    })
    const assertion = await provider.finish({
      payload: { initData: signInitData(validFields()) },
    })

    expect(provider.id).toBe(TELEGRAM_MINI_APP_PROVIDER_ID)
    expect(assertion).toEqual({
      provider: TELEGRAM_MINI_APP_PROVIDER_ID,
      providerUserId: '67890',
      displayName: 'Max User',
      metadata: {
        authDate: now.toISOString(),
        queryId: 'query-1',
        startParam: 'launch',
        username: 'max_user',
        languageCode: 'ru',
        photoUrl: 'https://example.com/avatar.png',
      },
    })
    expect(assertion.metadata).not.toHaveProperty('initData')
  })

  it('uses Telegram provider assertions through the existing sign-in pipeline', async () => {
    const kit = createInMemoryAuthKit()
    const provider = createTelegramMiniAppProvider({
      botToken,
      clock: { now: () => now },
      maxAgeSeconds: 60,
    })

    kit.providerRegistry.register(provider)

    const result = await kit.service.signIn({
      provider: TELEGRAM_MINI_APP_PROVIDER_ID,
      finishInput: { payload: signInitData(validFields()) },
      now,
    })

    expect(result.identity.provider).toBe(TELEGRAM_MINI_APP_PROVIDER_ID)
    expect(result.identity.providerUserId).toBe('67890')
    expect(result.identity.metadata).toMatchObject({ username: 'max_user' })
    expect(kit.store.listAuditEvents().map((event) => event.type)).toContain(AuditEventType.SignIn)
  })

  it('extracts MAX WebAppData from URL fragments and maps it into assertions', async () => {
    const initData = signInitData(validFields())
    const params = new URLSearchParams({
      WebAppData: initData,
      WebAppPlatform: 'web',
      WebAppVersion: '26.2.8',
    })
    const url = `https://example.com#${params.toString()}`
    const provider = createMaxWebAppProvider({
      botToken,
      providerId: 'max',
      clock: { now: () => now },
      maxAgeSeconds: 60,
    })

    const assertion = await provider.finish({ payload: { url } })

    expect(assertion.provider).toBe('max')
    expect(assertion.providerUserId).toBe('67890')
    expect(assertion.displayName).toBe('Max User')
  })

  it('accepts direct MAX init data and keeps metadata optional', async () => {
    const provider = createMaxWebAppProvider({ botToken })
    const initData = signInitData({
      user: JSON.stringify({ id: 100, username: 'fallback_name' }),
    })
    const assertion = await provider.finish({ payload: initData })

    expect(provider.id).toBe(MAX_WEBAPP_PROVIDER_ID)
    expect(assertion).toEqual({
      provider: MAX_WEBAPP_PROVIDER_ID,
      providerUserId: '100',
      displayName: 'fallback_name',
      metadata: {
        username: 'fallback_name',
      },
    })
  })

  it('omits display metadata when signed user data has only an id', async () => {
    const provider = createTelegramMiniAppProvider({ botToken })
    const assertion = await provider.finish({
      payload: signInitData({ user: JSON.stringify({ id: 'user-only-id' }) }),
    })

    expect(assertion).toEqual({
      provider: TELEGRAM_MINI_APP_PROVIDER_ID,
      providerUserId: 'user-only-id',
    })
  })

  it('trims signed user display fields and omits blank profile metadata', async () => {
    const provider = createTelegramMiniAppProvider({ botToken })
    const assertion = await provider.finish({
      payload: signInitData({
        user: JSON.stringify({
          id: '  trimmed-user-id  ',
          first_name: '  Trimmed  ',
          last_name: ' User ',
          username: '   ',
          language_code: '',
          photo_url: '   ',
        }),
      }),
    })

    expect(assertion).toEqual({
      provider: TELEGRAM_MINI_APP_PROVIDER_ID,
      providerUserId: 'trimmed-user-id',
      displayName: 'Trimmed User',
    })
  })

  it('rejects invalid signatures, malformed hashes, duplicates, and missing hashes', async () => {
    const initData = signInitData(validFields())
    const wrongHash = signInitData(validFields(), 'wrong-bot-token')

    await expectInvalid(() => validateSignedWebAppInitData({ initData: wrongHash, botToken }))
    await expectInvalid(() =>
      validateSignedWebAppInitData({
        initData: 'user=%7B%22id%22%3A1%7D&hash=not-hex',
        botToken,
      }),
    )
    await expectInvalid(() =>
      validateSignedWebAppInitData({
        initData: 'user=%7B%22id%22%3A1%7D',
        botToken,
      }),
    )
    await expectInvalid(() =>
      validateSignedWebAppInitData({
        initData: `${initData}&query_id=duplicate`,
        botToken,
      }),
    )
    await expectInvalid(() =>
      validateSignedWebAppInitData({
        initData: `${initData}&hash=${'1'.repeat(64)}`,
        botToken,
      }),
    )
  })

  it('rejects invalid auth_date and max-age options', async () => {
    await expectInvalid(() =>
      validateSignedWebAppInitData({
        initData: signInitData(validFields({ auth_date: 'not-a-number' })),
        botToken,
      }),
    )
    await expectInvalid(() =>
      validateSignedWebAppInitData({
        initData: signInitData(validFields({ auth_date: '0' })),
        botToken,
      }),
    )
    await expectInvalid(() =>
      validateSignedWebAppInitData({
        initData: signInitData({ user: JSON.stringify({ id: 1 }) }),
        botToken,
        maxAgeSeconds: 60,
        now,
      }),
    )
    await expectInvalid(() =>
      validateSignedWebAppInitData({
        initData: signInitData(validFields({ auth_date: '1' })),
        botToken,
        maxAgeSeconds: 60,
        now,
      }),
    )
    await expectInvalid(() =>
      validateSignedWebAppInitData({
        initData: signInitData(validFields({ auth_date: `${Number(authDateSeconds) + 10}` })),
        botToken,
        maxAgeSeconds: 60,
        now,
      }),
    )
    await expectInvalid(() =>
      validateSignedWebAppInitData({
        initData: signInitData(validFields()),
        botToken: '',
      }),
    )
    await expectInvalid(() =>
      validateSignedWebAppInitData({
        initData: signInitData(validFields()),
        botToken,
        maxAgeSeconds: Number.POSITIVE_INFINITY,
      }),
    )
  })

  it('rejects missing payloads and malformed WebApp users', async () => {
    const provider = createTelegramMiniAppProvider({ botToken })

    await expectInvalid(() => provider.finish({}))
    await expectInvalid(() => provider.finish({ payload: { other: true } }))
    await expectInvalid(() => provider.finish({ payload: signInitData({}) }))
    await expectInvalid(() => provider.finish({ payload: signInitData({ user: '{' }) }))
    await expectInvalid(() => provider.finish({ payload: signInitData({ user: '[]' }) }))
    await expectInvalid(() =>
      provider.finish({ payload: signInitData({ user: '{"first_name":"No Id"}' }) }),
    )
    await expectInvalid(() =>
      provider.finish({ payload: signInitData({ user: JSON.stringify({ id: '   ' }) }) }),
    )
    await expectInvalid(() =>
      provider.finish({ payload: signInitData({ user: JSON.stringify({ id: Number.NaN }) }) }),
    )
    await expectInvalid(() =>
      provider.finish({
        payload: signInitData({ user: JSON.stringify({ id: Number.POSITIVE_INFINITY }) }),
      }),
    )
  })

  it('rejects non-string public validator inputs without TypeErrors', async () => {
    await expectInvalid(() =>
      validateSignedWebAppInitData({
        initData: undefined as unknown as string,
        botToken,
      }),
    )
    await expectInvalid(() =>
      validateSignedWebAppInitData({
        initData: signInitData(validFields()),
        botToken: undefined as unknown as string,
      }),
    )
  })

  it('rejects fractional max-age options', async () => {
    await expectInvalid(() =>
      validateSignedWebAppInitData({
        initData: signInitData(validFields()),
        botToken,
        maxAgeSeconds: 1.5,
      }),
    )
  })

  it('rejects blank WebAppData values in MAX URL fragments', async () => {
    const provider = createMaxWebAppProvider({ botToken })

    await expectInvalid(() => provider.finish({ payload: 'WebAppData=&WebAppPlatform=web' }))
  })

  it('rejects invalid MAX WebAppData URL fragments', async () => {
    const provider = createMaxWebAppProvider({ botToken })

    await expectInvalid(() => provider.finish({ payload: 'https://example.com' }))
    await expectInvalid(() =>
      provider.finish({ payload: 'WebAppData=one&WebAppData=two&WebAppPlatform=web' }),
    )
  })

  it('accepts MAX raw fragment payloads without a full URL', async () => {
    const initData = signInitData({
      start_param: 'contains-WebAppData=value',
      user: JSON.stringify({ user_id: 777, first_name: 'Raw' }),
    })
    const provider = createMaxWebAppProvider({ botToken })
    const assertion = await provider.finish({
      payload: `WebAppData=${encodeURIComponent(initData)}&WebAppPlatform=web`,
    })

    expect(assertion.providerUserId).toBe('777')
    expect(assertion.displayName).toBe('Raw')
  })
})
