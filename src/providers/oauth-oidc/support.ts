import type { FinishInput } from '../../domain/types.js'
import { invalidInput } from '../../errors.js'

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

export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

export function readFinishPayload(input: FinishInput): Record<string, unknown> {
  return isRecord(input.payload) ? input.payload : {}
}
