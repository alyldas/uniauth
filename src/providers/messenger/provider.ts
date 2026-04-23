import type {
  AuthIdentityProvider,
  Clock,
  FinishInput,
  ProviderIdentityAssertion,
} from '../../domain/types.js'
import type { AuthProvider } from '../../ports.js'
import { optionalProp } from '../../utils/optional.js'
import { MAX_WEBAPP_PROVIDER_ID, TELEGRAM_MINI_APP_PROVIDER_ID } from './constants.js'
import { normalizeMaxWebAppInitData, readWebAppInitData } from './payload.js'
import {
  type SignedWebAppInitDataValidationResult,
  validateSignedWebAppInitData,
} from './signed-webapp.js'
import { invalidSignedWebAppInitData, isRecord, readString } from './support.js'

export interface MessengerWebAppProviderOptions {
  readonly botToken: string
  readonly providerId?: AuthIdentityProvider
  readonly clock?: Clock
  readonly maxAgeSeconds?: number
}

interface MessengerWebAppUser {
  readonly id: string
  readonly firstName?: string
  readonly lastName?: string
  readonly username?: string
  readonly languageCode?: string
  readonly photoUrl?: string
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
        ...optionalProp('now', options.clock?.now()),
        ...optionalProp('maxAgeSeconds', options.maxAgeSeconds),
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
    ...optionalProp('displayName', displayName),
    ...optionalProp('metadata', metadata),
  }
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
    ...optionalProp('firstName', readString(user.first_name)),
    ...optionalProp('lastName', readString(user.last_name)),
    ...optionalProp('username', readString(user.username)),
    ...optionalProp('languageCode', readString(user.language_code)),
    ...optionalProp('photoUrl', readString(user.photo_url)),
  }
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

function readUserId(value: unknown): string | undefined {
  if (typeof value === 'string') {
    return value.trim() || undefined
  }

  if (typeof value === 'number' && Number.isFinite(value)) {
    return String(value)
  }

  return undefined
}

function formatDisplayName(user: MessengerWebAppUser): string | undefined {
  return [user.firstName, user.lastName].filter(Boolean).join(' ') || user.username
}

function buildMessengerWebAppMetadata(
  validated: SignedWebAppInitDataValidationResult,
  user: MessengerWebAppUser,
): Record<string, string> | undefined {
  const metadata = {
    ...optionalProp('authDate', validated.authDate?.toISOString()),
    ...optionalProp('queryId', validated.fields.query_id),
    ...optionalProp('startParam', validated.fields.start_param),
    ...optionalProp('username', user.username),
    ...optionalProp('languageCode', user.languageCode),
    ...optionalProp('photoUrl', user.photoUrl),
  }

  return Object.keys(metadata).length > 0 ? metadata : undefined
}
