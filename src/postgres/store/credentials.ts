import { UniAuthError, UniAuthErrorCode } from '../../errors.js'
import type { CredentialRepo } from '../../contracts.js'
import {
  buildUpdateQuery,
  mapCredentialRow,
  mapCredentialWriteError,
  type CredentialRow,
  type PostgresStoreContext,
} from './shared.js'

export function createCredentialRepo(context: PostgresStoreContext): CredentialRepo {
  const repo: CredentialRepo = {
    findPasswordByEmail: async (email) =>
      context.queryOptionalRow<CredentialRow, ReturnType<typeof mapCredentialRow>>(
        `select
           id, user_id, type, subject, password_hash, created_at, updated_at, metadata
         from uniauth_credentials
         where type = 'password' and subject = $1`,
        [email],
        mapCredentialRow,
      ),
    findPasswordByUserId: async (userId) =>
      context.queryOptionalRow<CredentialRow, ReturnType<typeof mapCredentialRow>>(
        `select
           id, user_id, type, subject, password_hash, created_at, updated_at, metadata
         from uniauth_credentials
         where type = 'password' and user_id = $1`,
        [userId],
        mapCredentialRow,
      ),
    listByUserId: async (userId) =>
      context.queryRows<CredentialRow, ReturnType<typeof mapCredentialRow>>(
        `select
           id, user_id, type, subject, password_hash, created_at, updated_at, metadata
         from uniauth_credentials
         where user_id = $1
         order by created_at asc, id asc`,
        [userId],
        mapCredentialRow,
      ),
    create: async (credential) => {
      try {
        return await context.queryRequiredRow<CredentialRow, ReturnType<typeof mapCredentialRow>>(
          `insert into uniauth_credentials (
             id, user_id, type, subject, password_hash, created_at, updated_at, metadata
           ) values ($1, $2, $3, $4, $5, $6, $7, $8)
           returning
             id, user_id, type, subject, password_hash, created_at, updated_at, metadata`,
          [
            credential.id,
            credential.userId,
            credential.type,
            credential.subject,
            credential.passwordHash,
            credential.createdAt,
            credential.updatedAt,
            credential.metadata ?? null,
          ],
          mapCredentialRow,
        )
      } catch (error) {
        throw mapCredentialWriteError(error)
      }
    },
    update: async (id, patch) => {
      const existing = await context.queryOptionalRow<
        CredentialRow,
        ReturnType<typeof mapCredentialRow>
      >(
        `select
           id, user_id, type, subject, password_hash, created_at, updated_at, metadata
         from uniauth_credentials
         where id = $1`,
        [id],
        mapCredentialRow,
      )

      if (!existing) {
        throw new UniAuthError(UniAuthErrorCode.CredentialNotFound, 'Credential was not found.')
      }

      const update = buildUpdateQuery(patch, [
        { key: 'userId', column: 'user_id' },
        { key: 'subject', column: 'subject' },
        { key: 'passwordHash', column: 'password_hash' },
        { key: 'updatedAt', column: 'updated_at' },
        { key: 'metadata', column: 'metadata' },
      ])

      if (!update) {
        return existing
      }

      try {
        return await context.queryRequiredRow<CredentialRow, ReturnType<typeof mapCredentialRow>>(
          `update uniauth_credentials
           set ${update.setClause}
           where id = $${update.values.length + 1}
           returning
             id, user_id, type, subject, password_hash, created_at, updated_at, metadata`,
          [...update.values, id],
          mapCredentialRow,
        )
      } catch (error) {
        throw mapCredentialWriteError(error)
      }
    },
  }

  return repo
}
