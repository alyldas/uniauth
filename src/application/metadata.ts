import { invalidInput } from '../errors.js'

export function normalizeMetadataRecord(
  metadata: Record<string, unknown> | undefined,
  name: string,
): Record<string, unknown> | undefined {
  if (metadata === undefined) {
    return undefined
  }

  if (!isPlainObject(metadata)) {
    throw invalidInput(`${name} must be a plain object.`)
  }

  return metadata
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    return false
  }

  const prototype = Object.getPrototypeOf(value) as unknown
  return prototype === Object.prototype || prototype === null
}
