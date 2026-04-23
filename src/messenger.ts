import { createHmac, timingSafeEqual } from 'node:crypto'
import type {
  AuthIdentityProvider,
  Clock,
  FinishInput,
  ProviderIdentityAssertion,
} from './domain/types.js'
import { invalidInput } from './errors.js'
import type { AuthProvider } from './ports.js'

export const TELEGRAM_MINI_APP_PROVIDER_ID = 'telegram-mini-app'
export const MAX_WEBAPP_PROVIDER_ID = 'max-webapp'

const WEBAPP_DATA_HMAC_KEY = 'WebAppData'
const SIGNED_WEBAPP_INIT_DATA_ERROR = 'Invalid signed WebApp init data.'
const WEBAPP_HASH_PATTERN = /^[a-f0-9]{64}$/i

export interface SignedWebAppInitDataValidationInput {
  readonly initData: string
  readonly botToken: string
  readonly now?: Date
  readonly maxAgeSeconds?: number
}

export interface SignedWebAppInitDataValidationResult {
  readonly fields: Readonly<Record<string, string>>
  readonly authDate?: Date
}

interface MessengerWebAppUser {
  readonly id: string
  readonly firstName?: string
  readonly lastName?: string
  readonly username?: string
  readonly languageCode?: string
  readonly photoUrl?: string
}

export interface MessengerWebAppProviderOptions {
  readonly botToken: string
  readonly providerId?: AuthIdentityProvider
  readonly clock?: Clock
  readonly maxAgeSeconds?: number
}

interface ParsedSignedWebAppInitData {
  readonly fields: Record<string, string>
  readonly hash: string
  readonly dataCheckString: string
}

export function validateSignedWebAppInitData(
  input: SignedWebAppInitDataValidationInput,
): SignedWebAppInitDataValidationResult {
  const botToken = requireNonBlankString(input.botToken, 'Bot token is required.')
  const maxAgeSeconds = validateNonNegativeSeconds(input.maxAgeSeconds, 'maxAgeSeconds')
  const parsed = parseSignedWebAppInitData(input.initData)
  const expectedHash = signWebAppInitData(parsed.dataCheckString, botToken)

  if (!timingSafeEqualHex(parsed.hash, expectedHash)) {
    throw invalidSignedWebAppInitData()
  }

  const authDate = parseAuthDate(parsed.fields.auth_date)

  enforceAuthDateMaxAge({
    ...definedProp('authDate', authDate),
    ...definedProp('maxAgeSeconds', maxAgeSeconds),
    ...definedProp('now', input.now),
  })

  return {
    fields: parsed.fields,
    ...definedProp('authDate', authDate),
  }
}

export function createTelegramMiniAppProvider(
  options: MessengerWebAppProviderOptions,
): AuthProvider {
  return createMessengerWebAppProvider({
    ...options,
    providerId: options.providerId ?? TELEGRAM_MINI_APP_PROVIDER_ID,
    resolveInitData: (value) => value,
  })
}

export function createMaxWebAppProvider(options: MessengerWebAppProviderOptions): AuthProvider {
  return createMessengerWebAppProvider({
    ...options,
    providerId: options.providerId ?? MAX_WEBAPP_PROVIDER_ID,
    resolveInitData: normalizeMaxWebAppInitData,
  })
}

function parseMessengerWebAppUser(fields: Readonly<Record<string, string>>): MessengerWebAppUser {
  const rawUser = fields.user

  if (!rawUser) {
    throw invalidSignedWebAppInitData()
  }

  const user = parseJsonRecord(rawUser)
  const id = readUserId(user.id ?? user.user_id)

  if (!id) {
    throw invalidSignedWebAppInitData()
  }

  return {
    id,
    ...definedProp('firstName', readString(user.first_name)),
    ...definedProp('lastName', readString(user.last_name)),
    ...definedProp('username', readString(user.username)),
    ...definedProp('languageCode', readString(user.language_code)),
    ...definedProp('photoUrl', readString(user.photo_url)),
  }
}

function createMessengerWebAppProvider(
  options: MessengerWebAppProviderOptions & {
    readonly providerId: AuthIdentityProvider
    readonly resolveInitData: (value: string) => string
  },
): AuthProvider {
  return {
    id: options.providerId,
    async finish(input: FinishInput): Promise<ProviderIdentityAssertion> {
      const initData = options.resolveInitData(readWebAppInitData(input))
      const validated = validateSignedWebAppInitData({
        initData,
        botToken: options.botToken,
        ...definedProp('now', options.clock?.now()),
        ...definedProp('maxAgeSeconds', options.maxAgeSeconds),
      })

      return mapMessengerWebAppAssertion(options.providerId, validated)
    },
  }
}

function mapMessengerWebAppAssertion(
  provider: AuthIdentityProvider,
  validated: SignedWebAppInitDataValidationResult,
): ProviderIdentityAssertion {
  const user = parseMessengerWebAppUser(validated.fields)
  const displayName = formatDisplayName(user)
  const metadata = buildMessengerWebAppMetadata(validated, user)

  return {
    provider,
    providerUserId: user.id,
    ...definedProp('displayName', displayName),
    ...definedProp('metadata', metadata),
  }
}

function parseSignedWebAppInitData(initData: string): ParsedSignedWebAppInitData {
  requireNonBlankString(initData, 'Signed WebApp init data is required.')

  const query = initData.startsWith('?') ? initData.slice(1) : initData
  const params = new URLSearchParams(query)
  const fields: Record<string, string> = {}
  const dataCheckEntries: Array<readonly [string, string]> = []
  let hash: string | undefined

  for (const [key, value] of params.entries()) {
    if (Object.hasOwn(fields, key) || (key === 'hash' && hash !== undefined)) {
      throw invalidSignedWebAppInitData()
    }

    if (key === 'hash') {
      hash = value
    } else {
      fields[key] = value
      dataCheckEntries.push([key, value])
    }
  }

  if (!hash || !WEBAPP_HASH_PATTERN.test(hash)) {
    throw invalidSignedWebAppInitData()
  }

  dataCheckEntries.sort(([left], [right]) => Number(left > right) - Number(left < right))

  return {
    fields,
    hash,
    dataCheckString: dataCheckEntries.map(([key, value]) => `${key}=${value}`).join('\n'),
  }
}

function signWebAppInitData(dataCheckString: string, botToken: string): string {
  const secretKey = createHmac('sha256', WEBAPP_DATA_HMAC_KEY).update(botToken).digest()

  return createHmac('sha256', secretKey).update(dataCheckString).digest('hex')
}

function timingSafeEqualHex(receivedHash: string, expectedHash: string): boolean {
  return timingSafeEqual(Buffer.from(receivedHash, 'hex'), Buffer.from(expectedHash, 'hex'))
}

function parseAuthDate(value: string | undefined): Date | undefined {
  if (value === undefined) {
    return undefined
  }

  const seconds = Number(value)

  if (!Number.isInteger(seconds)) {
    throw invalidSignedWebAppInitData()
  }

  if (seconds <= 0) {
    throw invalidSignedWebAppInitData()
  }

  return new Date(seconds * 1000)
}

function enforceAuthDateMaxAge(input: {
  readonly authDate?: Date
  readonly maxAgeSeconds?: number
  readonly now?: Date
}): void {
  if (input.maxAgeSeconds === undefined) {
    return
  }

  if (!input.authDate) {
    throw invalidSignedWebAppInitData()
  }

  const now = input.now ?? new Date()
  const minTime = now.getTime() - input.maxAgeSeconds * 1000
  const authTime = input.authDate.getTime()

  if (authTime < minTime || authTime > now.getTime()) {
    throw invalidSignedWebAppInitData()
  }
}

function readWebAppInitData(input: FinishInput): string {
  if (typeof input.payload === 'string') {
    return input.payload
  }

  if (isRecord(input.payload)) {
    const initData = readString(input.payload.initData)

    if (initData) {
      return initData
    }

    const url = readString(input.payload.url)

    if (url) {
      return url
    }
  }

  throw invalidInput('Signed WebApp init data payload is required.')
}

function normalizeMaxWebAppInitData(value: string): string {
  return isMaxWebAppDataContainer(value) ? extractMaxWebAppInitData(value) : value
}

function isMaxWebAppDataContainer(value: string): boolean {
  return value.includes('#') || value.startsWith('WebAppData=') || value.includes('&WebAppData=')
}

function extractUrlFragment(value: string): string {
  const hashIndex = value.indexOf('#')

  if (hashIndex === -1) {
    return value
  }

  return value.slice(hashIndex + 1)
}

function extractMaxWebAppInitData(value: string): string {
  const params = new URLSearchParams(extractUrlFragment(value))
  const seen = new Set<string>()

  for (const key of params.keys()) {
    if (seen.has(key)) {
      throw invalidSignedWebAppInitData()
    }

    seen.add(key)
  }

  const appData = params.get('WebAppData')

  if (!appData) {
    throw invalidSignedWebAppInitData()
  }

  return appData
}

function parseJsonRecord(value: string): Record<string, unknown> {
  try {
    const parsed: unknown = JSON.parse(value)

    if (isRecord(parsed)) {
      return parsed
    }
  } catch {
    throw invalidSignedWebAppInitData()
  }

  throw invalidSignedWebAppInitData()
}

function formatDisplayName(user: MessengerWebAppUser): string | undefined {
  return [user.firstName, user.lastName].filter(Boolean).join(' ') || user.username
}

function buildMessengerWebAppMetadata(
  validated: SignedWebAppInitDataValidationResult,
  user: MessengerWebAppUser,
): Record<string, string> | undefined {
  const metadata = {
    ...definedProp('authDate', validated.authDate?.toISOString()),
    ...definedProp('queryId', validated.fields.query_id),
    ...definedProp('startParam', validated.fields.start_param),
    ...definedProp('username', user.username),
    ...definedProp('languageCode', user.languageCode),
    ...definedProp('photoUrl', user.photoUrl),
  }

  return Object.keys(metadata).length > 0 ? metadata : undefined
}

function validateNonNegativeSeconds(value: number | undefined, name: string): number | undefined {
  if (value === undefined) {
    return undefined
  }

  if (!Number.isInteger(value) || value < 0) {
    throw invalidInput(`${name} must be a non-negative integer.`)
  }

  return value
}

function requireNonBlankString(value: unknown, message: string): string {
  if (typeof value !== 'string' || !value.trim()) {
    throw invalidInput(message)
  }

  return value
}

function readString(value: unknown): string | undefined {
  if (typeof value !== 'string') {
    return undefined
  }

  return value.trim() || undefined
}

function readUserId(value: unknown): string | undefined {
  if (typeof value === 'string') {
    return value.trim() || undefined
  }

  if (typeof value === 'number' && Number.isFinite(value)) {
    return String(value)
  }

  return undefined
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function definedProp<Key extends string, Value>(
  key: Key,
  value: Value | undefined,
): { [Property in Key]: Value } | Record<never, never> {
  return value === undefined ? {} : ({ [key]: value } as { [Property in Key]: Value })
}

function invalidSignedWebAppInitData(): Error {
  return invalidInput(SIGNED_WEBAPP_INIT_DATA_ERROR)
}
