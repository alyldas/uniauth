import { createHmac, timingSafeEqual } from 'node:crypto'
import { invalidInput } from '../../errors.js'
import { optionalProp } from '../../utils/optional.js'
import { invalidSignedWebAppInitData, requireNonBlankString } from './support.js'

const WEBAPP_DATA_HMAC_KEY = 'WebAppData'
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
    ...optionalProp('authDate', authDate),
    ...optionalProp('maxAgeSeconds', maxAgeSeconds),
    ...optionalProp('now', input.now),
  })

  return {
    fields: parsed.fields,
    ...optionalProp('authDate', authDate),
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

function validateNonNegativeSeconds(value: number | undefined, name: string): number | undefined {
  if (value === undefined) {
    return undefined
  }

  if (!Number.isInteger(value) || value < 0) {
    throw invalidInput(`${name} must be a non-negative integer.`)
  }

  return value
}
