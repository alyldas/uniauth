import { invalidInput } from '../../errors.js'

const SIGNED_WEBAPP_INIT_DATA_ERROR = 'Invalid signed WebApp init data.'

export function invalidSignedWebAppInitData(): Error {
  return invalidInput(SIGNED_WEBAPP_INIT_DATA_ERROR)
}

export function requireNonBlankString(value: unknown, message: string): string {
  if (typeof value !== 'string' || !value.trim()) {
    throw invalidInput(message)
  }

  return value
}

export function readString(value: unknown): string | undefined {
  if (typeof value !== 'string') {
    return undefined
  }

  return value.trim() || undefined
}

export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}
