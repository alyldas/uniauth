import { UniAuthError, UniAuthErrorCode } from '../../errors.js'
import type { VerificationRepo } from '../../contracts.js'
import {
  buildUpdateQuery,
  mapVerificationRow,
  type PostgresStoreContext,
  type VerificationRow,
} from './shared.js'

export function createVerificationRepo(context: PostgresStoreContext): VerificationRepo {
  const repo: VerificationRepo = {
    findById: async (id) =>
      context.queryOptionalRow<VerificationRow, ReturnType<typeof mapVerificationRow>>(
        `select
           id, purpose, target, provider, channel, secret_hash, status, created_at, expires_at,
           consumed_at, metadata
         from uniauth_verifications
         where id = $1`,
        [id],
        mapVerificationRow,
      ),
    findByIdForUpdate: async (id) =>
      context.queryOptionalRow<VerificationRow, ReturnType<typeof mapVerificationRow>>(
        `select
           id, purpose, target, provider, channel, secret_hash, status, created_at, expires_at,
           consumed_at, metadata
         from uniauth_verifications
         where id = $1
         for update`,
        [id],
        mapVerificationRow,
      ),
    create: async (verification) =>
      context.queryRequiredRow<VerificationRow, ReturnType<typeof mapVerificationRow>>(
        `insert into uniauth_verifications (
           id, purpose, target, provider, channel, secret_hash, status, created_at, expires_at,
           consumed_at, metadata
         ) values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
         returning
           id, purpose, target, provider, channel, secret_hash, status, created_at, expires_at,
           consumed_at, metadata`,
        [
          verification.id,
          verification.purpose,
          verification.target,
          verification.provider ?? null,
          verification.channel ?? null,
          verification.secretHash,
          verification.status,
          verification.createdAt,
          verification.expiresAt,
          verification.consumedAt ?? null,
          verification.metadata ?? null,
        ],
        mapVerificationRow,
      ),
    update: async (id, patch) => {
      const existing = await repo.findById(id)

      if (!existing) {
        throw new UniAuthError(UniAuthErrorCode.VerificationNotFound, 'Verification was not found.')
      }

      const update = buildUpdateQuery(patch, [
        { key: 'purpose', column: 'purpose' },
        { key: 'target', column: 'target' },
        { key: 'provider', column: 'provider' },
        { key: 'channel', column: 'channel' },
        { key: 'secretHash', column: 'secret_hash' },
        { key: 'status', column: 'status' },
        { key: 'expiresAt', column: 'expires_at' },
        { key: 'consumedAt', column: 'consumed_at' },
        { key: 'metadata', column: 'metadata' },
      ])

      if (!update) {
        return existing
      }

      return context.queryRequiredRow<VerificationRow, ReturnType<typeof mapVerificationRow>>(
        `update uniauth_verifications
         set ${update.setClause}
         where id = $${update.values.length + 1}
         returning
           id, purpose, target, provider, channel, secret_hash, status, created_at, expires_at,
           consumed_at, metadata`,
        [...update.values, id],
        mapVerificationRow,
      )
    },
  }

  return repo
}
