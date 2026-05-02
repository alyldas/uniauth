import type { AuditLogRepo } from '../../ports.js'
import { type AuditEventQuery } from '../../domain/types.js'
import { type AuditEventRow, mapAuditEventRow, type PostgresStoreContext } from './shared.js'

export function createAuditLogRepo(context: PostgresStoreContext): AuditLogRepo {
  return {
    append: async (event) => {
      await context.query(
        `insert into uniauth_audit_events (
           id, type, occurred_at, user_id, identity_id, session_id, metadata
         ) values ($1, $2, $3, $4, $5, $6, $7)`,
        [
          event.id,
          event.type,
          event.occurredAt,
          event.userId ?? null,
          event.identityId ?? null,
          event.sessionId ?? null,
          event.metadata ?? null,
        ],
      )
    },
    list: async (input: AuditEventQuery = {}) => {
      const filters: string[] = []
      const values: unknown[] = []

      if (input.userId) {
        values.push(input.userId)
        filters.push(`user_id = $${values.length}`)
      }

      if (input.identityId) {
        values.push(input.identityId)
        filters.push(`identity_id = $${values.length}`)
      }

      if (input.sessionId) {
        values.push(input.sessionId)
        filters.push(`session_id = $${values.length}`)
      }

      if (input.type) {
        values.push(input.type)
        filters.push(`type = $${values.length}`)
      }

      if (input.before) {
        values.push(input.before.occurredAt)
        const beforeOccurredIndex = values.length
        values.push(input.before.id)
        const beforeIdIndex = values.length
        filters.push(
          `(occurred_at < $${beforeOccurredIndex} or (occurred_at = $${beforeOccurredIndex} and id < $${beforeIdIndex}))`,
        )
      }

      if (input.after) {
        values.push(input.after.occurredAt)
        const afterOccurredIndex = values.length
        values.push(input.after.id)
        const afterIdIndex = values.length
        filters.push(
          `(occurred_at > $${afterOccurredIndex} or (occurred_at = $${afterOccurredIndex} and id > $${afterIdIndex}))`,
        )
      }

      const whereClause = filters.length > 0 ? `where ${filters.join(' and ')}` : ''

      if (input.limit !== undefined) {
        values.push(input.limit)
      }

      const limitClause = input.limit !== undefined ? `limit $${values.length}` : ''

      return context.queryRows<AuditEventRow, ReturnType<typeof mapAuditEventRow>>(
        `select id, type, occurred_at, user_id, identity_id, session_id, metadata
           from uniauth_audit_events
           ${whereClause}
           order by occurred_at desc, id desc
           ${limitClause}`,
        values,
        (row) => mapAuditEventRow(row),
      )
    },
  }
}
