import type { AuthServiceRuntime } from './runtime.js'
import {
  toAuditEventCursor,
  type AuditEvent,
  type AuditEventCursor,
  type AuditEventPage,
  type AuditEventQuery,
} from '../domain/types.js'
import { invalidInput } from '../errors.js'
import { assertValidDate } from '../utils/time.js'

const DefaultAuditEventLimit = 50

interface NormalizedAuditEventQuery extends AuditEventQuery {
  readonly limit: number
}

export async function getAuditEvents(
  runtime: AuthServiceRuntime,
  input: AuditEventQuery = {},
): Promise<readonly AuditEvent[]> {
  const query = normalizeAuditEventQuery(input)
  return runtime.repos.auditLogRepo.list(query)
}

export async function getAuditEventPage(
  runtime: AuthServiceRuntime,
  input: AuditEventQuery = {},
): Promise<AuditEventPage> {
  const query = normalizeAuditEventQuery(input)
  const matchingEvents = await runtime.repos.auditLogRepo.list({
    ...query,
    limit: query.limit + 1,
  })
  const events = matchingEvents.slice(0, query.limit)
  const nextCursor =
    matchingEvents.length > query.limit && events.length > 0
      ? toAuditEventCursor(events.at(-1)!)
      : undefined

  return {
    events,
    ...(nextCursor ? { nextCursor } : {}),
  }
}

function normalizeAuditEventQuery(input: AuditEventQuery): NormalizedAuditEventQuery {
  if (!isAuditEventQuery(input)) {
    throw invalidInput('Audit event query is invalid.')
  }

  const before = input.before ? normalizeAuditEventCursor(input.before) : undefined
  const after = input.after ? normalizeAuditEventCursor(input.after) : undefined

  const limit = input.limit ?? DefaultAuditEventLimit

  if (!Number.isInteger(limit) || limit <= 0) {
    throw invalidInput('Audit event limit must be a positive integer.')
  }

  if (input.type !== undefined) {
    if (typeof input.type !== 'string') {
      throw invalidInput('Audit event type is invalid.')
    }

    const type = input.type.trim() as AuditEventQuery['type']

    if (!type) {
      throw invalidInput('Audit event type is invalid.')
    }

    return {
      ...input,
      type,
      ...(before ? { before } : {}),
      ...(after ? { after } : {}),
      limit,
    }
  }

  return {
    ...input,
    ...(before ? { before } : {}),
    ...(after ? { after } : {}),
    limit,
  }
}

function normalizeAuditEventCursor(input: AuditEventCursor): AuditEventCursor {
  if (!(input && typeof input === 'object')) {
    throw invalidInput('Audit event cursor is invalid.')
  }

  const occurredAt = input.occurredAt

  if (!(occurredAt instanceof Date)) {
    throw invalidInput('Audit event cursor time is invalid.')
  }

  assertValidDate(occurredAt, 'Audit event cursor time is invalid.')

  if (typeof input.id !== 'string') {
    throw invalidInput('Audit event cursor id is invalid.')
  }

  const id = input.id.trim()

  if (!id) {
    throw invalidInput('Audit event cursor id is invalid.')
  }

  return {
    occurredAt,
    id: id as AuditEventCursor['id'],
  }
}

function isAuditEventQuery(value: unknown): value is AuditEventQuery {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}
