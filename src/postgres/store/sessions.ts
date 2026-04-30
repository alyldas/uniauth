import { UniAuthError, UniAuthErrorCode } from '../../errors.js'
import type { SessionRepo } from '../../ports.js'
import {
  buildUpdateQuery,
  mapSessionRow,
  type PostgresStoreContext,
  type SessionRow,
} from './shared.js'

export function createSessionRepo(context: PostgresStoreContext): SessionRepo {
  const repo: SessionRepo = {
    findById: async (id) =>
      context.queryOptionalRow<SessionRow, ReturnType<typeof mapSessionRow>>(
        `select
           id, user_id, token_hash, status, created_at, expires_at, revoked_at, last_seen_at,
           metadata
         from uniauth_sessions
         where id = $1`,
        [id],
        mapSessionRow,
      ),
    findByTokenHash: async (tokenHash) =>
      context.queryOptionalRow<SessionRow, ReturnType<typeof mapSessionRow>>(
        `select
           id, user_id, token_hash, status, created_at, expires_at, revoked_at, last_seen_at,
           metadata
         from uniauth_sessions
         where token_hash = $1`,
        [tokenHash],
        mapSessionRow,
      ),
    listByUserId: async (userId) =>
      context.queryRows<SessionRow, ReturnType<typeof mapSessionRow>>(
        `select
           id, user_id, token_hash, status, created_at, expires_at, revoked_at, last_seen_at,
           metadata
         from uniauth_sessions
         where user_id = $1
         order by created_at asc, id asc`,
        [userId],
        mapSessionRow,
      ),
    create: async (session) =>
      context.queryRequiredRow<SessionRow, ReturnType<typeof mapSessionRow>>(
        `insert into uniauth_sessions (
           id, user_id, token_hash, status, created_at, expires_at, revoked_at, last_seen_at,
           metadata
         ) values ($1, $2, $3, $4, $5, $6, $7, $8, $9)
         returning
           id, user_id, token_hash, status, created_at, expires_at, revoked_at, last_seen_at,
           metadata`,
        [
          session.id,
          session.userId,
          session.tokenHash,
          session.status,
          session.createdAt,
          session.expiresAt,
          session.revokedAt ?? null,
          session.lastSeenAt ?? null,
          session.metadata ?? null,
        ],
        mapSessionRow,
      ),
    update: async (id, patch) => {
      const existing = await repo.findById(id)

      if (!existing) {
        throw new UniAuthError(UniAuthErrorCode.SessionNotFound, 'Session was not found.')
      }

      const update = buildUpdateQuery(patch, [
        { key: 'userId', column: 'user_id' },
        { key: 'tokenHash', column: 'token_hash' },
        { key: 'status', column: 'status' },
        { key: 'expiresAt', column: 'expires_at' },
        { key: 'revokedAt', column: 'revoked_at' },
        { key: 'lastSeenAt', column: 'last_seen_at' },
        { key: 'metadata', column: 'metadata' },
      ])

      if (!update) {
        return existing
      }

      return context.queryRequiredRow<SessionRow, ReturnType<typeof mapSessionRow>>(
        `update uniauth_sessions
         set ${update.setClause}
         where id = $${update.values.length + 1}
         returning
           id, user_id, token_hash, status, created_at, expires_at, revoked_at, last_seen_at,
           metadata`,
        [...update.values, id],
        mapSessionRow,
      )
    },
  }

  return repo
}
