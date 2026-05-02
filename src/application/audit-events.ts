import type { AuthServiceRuntime } from './runtime.js'
import type { AuditEvent, AuditEventCursor, AuditEventQuery } from '../domain/types.js'
import { invalidInput } from '../errors.js'
import { assertValidDate } from '../utils/time.js'

const DefaultAuditEventLimit = 50

export async function getAuditEvents(
  runtime: AuthServiceRuntime,
  input: AuditEventQuery = {},
): Promise<readonly AuditEvent[]> {
  const query = normalizeAuditEventQuery(input)
  return runtime.repos.auditLogRepo.list(query)
}

function normalizeAuditEventQuery(input: AuditEventQuery): AuditEventQuery {
  const before = input.before ? normalizeAuditEventCursor(input.before) : undefined
  const after = input.after ? normalizeAuditEventCursor(input.after) : undefined

  const limit = input.limit ?? DefaultAuditEventLimit

  if (!Number.isInteger(limit) || limit <= 0) {
    throw invalidInput('Audit event limit must be a positive integer.')
  }

  if (input.type !== undefined) {
    const type = input.type.trim()

    if (!type) {
      throw invalidInput('Audit event type is invalid.')
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
