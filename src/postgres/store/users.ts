import { UniAuthError, UniAuthErrorCode } from '../../errors.js'
import type { UserRepo } from '../../contracts.js'
import { buildUpdateQuery, mapUserRow, type PostgresStoreContext, type UserRow } from './shared.js'

export function createUserRepo(context: PostgresStoreContext): UserRepo {
  const repo: UserRepo = {
    findById: async (id) =>
      context.queryOptionalRow<UserRow, ReturnType<typeof mapUserRow>>(
        `select id, display_name, email, phone, created_at, updated_at, disabled_at, metadata
         from uniauth_users
         where id = $1`,
        [id],
        mapUserRow,
      ),
    create: async (user) =>
      context.queryRequiredRow<UserRow, ReturnType<typeof mapUserRow>>(
        `insert into uniauth_users (
           id, display_name, email, phone, created_at, updated_at, disabled_at, metadata
         ) values ($1, $2, $3, $4, $5, $6, $7, $8)
         returning id, display_name, email, phone, created_at, updated_at, disabled_at, metadata`,
        [
          user.id,
          user.displayName ?? null,
          user.email ?? null,
          user.phone ?? null,
          user.createdAt,
          user.updatedAt,
          user.disabledAt ?? null,
          user.metadata ?? null,
        ],
        mapUserRow,
      ),
    update: async (id, patch) => {
      const existing = await repo.findById(id)

      if (!existing) {
        throw new UniAuthError(UniAuthErrorCode.UserNotFound, 'User was not found.')
      }

      const update = buildUpdateQuery(patch, [
        { key: 'displayName', column: 'display_name' },
        { key: 'email', column: 'email' },
        { key: 'phone', column: 'phone' },
        { key: 'updatedAt', column: 'updated_at' },
        { key: 'disabledAt', column: 'disabled_at' },
        { key: 'metadata', column: 'metadata' },
      ])

      if (!update) {
        return existing
      }

      return context.queryRequiredRow<UserRow, ReturnType<typeof mapUserRow>>(
        `update uniauth_users
         set ${update.setClause}
         where id = $${update.values.length + 1}
         returning id, display_name, email, phone, created_at, updated_at, disabled_at, metadata`,
        [...update.values, id],
        mapUserRow,
      )
    },
  }

  return repo
}
