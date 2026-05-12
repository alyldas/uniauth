import { invalidInput } from '../errors.js'

export function requireNonBlankString(value: unknown, message: string): string {
  if (typeof value !== 'string' || !value.trim()) {
    throw invalidInput(message)
  }

  return value.trim()
}

export function readString(value: unknown): string | undefined {
  if (typeof value !== 'string') {
    return undefined
  }

  return value.trim() || undefined
}

export function readBooleanLike(value: unknown): boolean | undefined {
  if (typeof value === 'boolean') {
    return value
  }

  if (typeof value !== 'string') {
    return undefined
  }

  const normalized = value.trim().toLowerCase()

  if (normalized === 'true') {
    return true
  }

  if (normalized === 'false') {
    return false
  }

  return undefined
}

export function requireMatchingStrings(
  left: string | undefined,
  right: string | undefined,
  message: string,
): void {
  if (left && right && left !== right) {
    throw invalidInput(message)
  }
}

export function buildMetadata(
  ...records: ReadonlyArray<Record<string, unknown> | undefined>
): Record<string, unknown> | undefined {
  const metadata: Record<string, unknown> = {}

  for (const record of records) {
    if (record === undefined) {
      continue
    }

    const normalizedRecord = requirePlainRecord(record, 'Bridge metadata must be a plain object.')

    for (const [key, value] of Object.entries(normalizedRecord)) {
      if (value !== undefined) {
        metadata[key] = value
      }
    }
  }

  return Object.keys(metadata).length > 0 ? metadata : undefined
}

function requirePlainRecord(value: unknown, message: string): Record<string, unknown> {
  if (!isPlainRecord(value)) {
    throw invalidInput(message)
  }

  return value
}

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    return false
  }

  const prototype = Object.getPrototypeOf(value)
  return prototype === Object.prototype || prototype === null
}
