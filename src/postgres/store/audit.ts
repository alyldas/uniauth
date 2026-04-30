import type { AuditLogRepo } from '../../ports.js'
import type { PostgresStoreContext } from './shared.js'

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
  }
}
