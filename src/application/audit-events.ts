import type { AuthServiceRuntime } from './runtime.js'
import type { AuditEvent, AuditEventQuery } from '../domain/types.js'
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
  if (input.before !== undefined) {
    assertValidDate(input.before, 'Audit event cursor time is invalid.')
  }

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
    limit,
  }
}
