import { UniAuthError, UniAuthErrorCode } from '../../errors.js'
import type { IdentityRepo } from '../../contracts.js'
import {
  buildUpdateQuery,
  mapIdentityRow,
  mapIdentityWriteError,
  type IdentityRow,
  type PostgresStoreContext,
} from './shared.js'

export function createIdentityRepo(context: PostgresStoreContext): IdentityRepo {
  const repo: IdentityRepo = {
    findById: async (id) =>
      context.queryOptionalRow<IdentityRow, ReturnType<typeof mapIdentityRow>>(
        `select
           id, user_id, provider, provider_user_id, status, email, email_verified, phone,
           phone_verified, trust, created_at, updated_at, disabled_at, metadata
         from uniauth_identities
         where id = $1`,
        [id],
        mapIdentityRow,
      ),
    findByProviderUserId: async (provider, providerUserId) =>
      context.queryOptionalRow<IdentityRow, ReturnType<typeof mapIdentityRow>>(
        `select
           id, user_id, provider, provider_user_id, status, email, email_verified, phone,
           phone_verified, trust, created_at, updated_at, disabled_at, metadata
         from uniauth_identities
         where provider = $1 and provider_user_id = $2`,
        [provider, providerUserId],
        mapIdentityRow,
      ),
    findByVerifiedEmail: async (email) =>
      context.queryRows<IdentityRow, ReturnType<typeof mapIdentityRow>>(
        `select
           id, user_id, provider, provider_user_id, status, email, email_verified, phone,
           phone_verified, trust, created_at, updated_at, disabled_at, metadata
         from uniauth_identities
         where status = 'active' and email_verified = true and email = $1
         order by created_at asc, id asc`,
        [email],
        mapIdentityRow,
      ),
    findByVerifiedPhone: async (phone) =>
      context.queryRows<IdentityRow, ReturnType<typeof mapIdentityRow>>(
        `select
           id, user_id, provider, provider_user_id, status, email, email_verified, phone,
           phone_verified, trust, created_at, updated_at, disabled_at, metadata
         from uniauth_identities
         where status = 'active' and phone_verified = true and phone = $1
         order by created_at asc, id asc`,
        [phone],
        mapIdentityRow,
      ),
    listByUserId: async (userId) =>
      context.queryRows<IdentityRow, ReturnType<typeof mapIdentityRow>>(
        `select
           id, user_id, provider, provider_user_id, status, email, email_verified, phone,
           phone_verified, trust, created_at, updated_at, disabled_at, metadata
         from uniauth_identities
         where user_id = $1
         order by created_at asc, id asc`,
        [userId],
        mapIdentityRow,
      ),
    create: async (identity) => {
      try {
        return await context.queryRequiredRow<IdentityRow, ReturnType<typeof mapIdentityRow>>(
          `insert into uniauth_identities (
             id, user_id, provider, provider_user_id, status, email, email_verified, phone,
             phone_verified, trust, created_at, updated_at, disabled_at, metadata
           ) values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
           returning
             id, user_id, provider, provider_user_id, status, email, email_verified, phone,
             phone_verified, trust, created_at, updated_at, disabled_at, metadata`,
          [
            identity.id,
            identity.userId,
            identity.provider,
            identity.providerUserId,
            identity.status,
            identity.email ?? null,
            identity.emailVerified ?? null,
            identity.phone ?? null,
            identity.phoneVerified ?? null,
            identity.trust ?? null,
            identity.createdAt,
            identity.updatedAt,
            identity.disabledAt ?? null,
            identity.metadata ?? null,
          ],
          mapIdentityRow,
        )
      } catch (error) {
        throw mapIdentityWriteError(error)
      }
    },
    update: async (id, patch) => {
      const existing = await repo.findById(id)

      if (!existing) {
        throw new UniAuthError(UniAuthErrorCode.IdentityNotFound, 'Identity was not found.')
      }

      const update = buildUpdateQuery(patch, [
        { key: 'userId', column: 'user_id' },
        { key: 'provider', column: 'provider' },
        { key: 'providerUserId', column: 'provider_user_id' },
        { key: 'status', column: 'status' },
        { key: 'email', column: 'email' },
        { key: 'emailVerified', column: 'email_verified' },
        { key: 'phone', column: 'phone' },
        { key: 'phoneVerified', column: 'phone_verified' },
        { key: 'trust', column: 'trust' },
        { key: 'updatedAt', column: 'updated_at' },
        { key: 'disabledAt', column: 'disabled_at' },
        { key: 'metadata', column: 'metadata' },
      ])

      if (!update) {
        return existing
      }

      try {
        return await context.queryRequiredRow<IdentityRow, ReturnType<typeof mapIdentityRow>>(
          `update uniauth_identities
           set ${update.setClause}
           where id = $${update.values.length + 1}
           returning
             id, user_id, provider, provider_user_id, status, email, email_verified, phone,
             phone_verified, trust, created_at, updated_at, disabled_at, metadata`,
          [...update.values, id],
          mapIdentityRow,
        )
      } catch (error) {
        throw mapIdentityWriteError(error)
      }
    },
    disableForUserIfAnotherActive: async (id, userId, patch) => {
      const activeIdentities = await context.queryRows<
        IdentityRow,
        ReturnType<typeof mapIdentityRow>
      >(
        `select
           id, user_id, provider, provider_user_id, status, email, email_verified, phone,
           phone_verified, trust, created_at, updated_at, disabled_at, metadata
         from uniauth_identities
         where user_id = $1 and status = 'active' and disabled_at is null
         order by created_at asc, id asc
         for update`,
        [userId],
        mapIdentityRow,
      )
      const target = activeIdentities.find((identity) => identity.id === id)

      if (!target) {
        throw new UniAuthError(UniAuthErrorCode.IdentityNotFound, 'Identity was not found.')
      }

      if (activeIdentities.length <= 1) {
        throw new UniAuthError(
          UniAuthErrorCode.LastIdentity,
          'Cannot unlink the last active identity.',
        )
      }

      return repo.update(id, patch)
    },
  }

  return repo
}
