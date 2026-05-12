import { link, unlink } from './accounts.js'
import { normalizeMetadataRecord } from './metadata.js'
import { optionalProp } from './optional.js'
import { changePassword, setPassword } from './passwords.js'
import type { AuthServiceRuntime } from './runtime.js'
import { resolveSessionContext } from './session-context.js'
import { revokeStoredSession, revokeUserSessions } from './sessions.js'
import { audit, ensureReAuth } from './support.js'
import type {
  ChangeCurrentAccountPasswordByTokenInput,
  CloseCurrentAccountByTokenInput,
  CloseCurrentAccountByTokenResult,
  Credential,
  LinkCurrentIdentityByTokenInput,
  LinkResult,
  RevokeOwnedSessionByTokenInput,
  RevokeOwnedSessionByTokenResult,
  SetCurrentAccountPasswordByTokenInput,
  UnlinkCurrentIdentityByTokenInput,
  UpdateCurrentAccountProfileByTokenInput,
  User,
} from '../domain/types.js'
import { AuditEventType, AuthPolicyAction, isActiveSession } from '../domain/types.js'
import { UniAuthError, UniAuthErrorCode, invalidInput } from '../errors.js'

const CurrentAccountProfileField = {
  DisplayName: 'displayName',
} as const

export async function revokeOwnedSessionByToken(
  runtime: AuthServiceRuntime,
  input: RevokeOwnedSessionByTokenInput,
): Promise<RevokeOwnedSessionByTokenResult> {
  return runtime.transaction.run(async () => {
    const now = input.now ?? runtime.clock.now()
    const { session, user } = await resolveSessionContext(runtime, {
      sessionToken: input.sessionToken,
      now,
    })
    const target = await runtime.repos.sessionRepo.findById(input.targetSessionId)

    if (!target || target.userId !== user.id || !isActiveSession(target, now)) {
      throw new UniAuthError(UniAuthErrorCode.SessionNotFound, 'Session was not found.')
    }

    await revokeStoredSession(runtime, target.id, now)

    return {
      currentSessionId: session.id,
      revokedSessionId: target.id,
      revokedCurrentSession: target.id === session.id,
    }
  })
}

export async function linkCurrentIdentityByToken(
  runtime: AuthServiceRuntime,
  input: LinkCurrentIdentityByTokenInput,
): Promise<LinkResult> {
  return runtime.transaction.run(async () => {
    const now = input.now ?? runtime.clock.now()
    const metadata = normalizeCurrentAccountMetadata(input.metadata)
    const { user } = await resolveSessionContext(runtime, {
      sessionToken: input.sessionToken,
      now,
    })

    return link(runtime, {
      userId: user.id,
      ...optionalProp('assertion', input.assertion),
      ...optionalProp('provider', input.provider),
      ...optionalProp('finishInput', input.finishInput),
      ...optionalProp('reAuthenticatedAt', input.reAuthenticatedAt),
      now,
      ...optionalProp('metadata', metadata),
    })
  })
}

export async function unlinkCurrentIdentityByToken(
  runtime: AuthServiceRuntime,
  input: UnlinkCurrentIdentityByTokenInput,
): Promise<void> {
  return runtime.transaction.run(async () => {
    const now = input.now ?? runtime.clock.now()
    const metadata = normalizeCurrentAccountMetadata(input.metadata)
    const { user } = await resolveSessionContext(runtime, {
      sessionToken: input.sessionToken,
      now,
    })

    await unlink(runtime, {
      userId: user.id,
      identityId: input.identityId,
      ...optionalProp('reAuthenticatedAt', input.reAuthenticatedAt),
      now,
      ...optionalProp('metadata', metadata),
    })
  })
}

export async function closeCurrentAccountByToken(
  runtime: AuthServiceRuntime,
  input: CloseCurrentAccountByTokenInput,
): Promise<CloseCurrentAccountByTokenResult> {
  return runtime.transaction.run(async () => {
    const now = input.now ?? runtime.clock.now()
    const metadata = normalizeCurrentAccountMetadata(input.metadata)
    const { session, user } = await resolveSessionContext(runtime, {
      sessionToken: input.sessionToken,
      now,
    })

    await ensureReAuth(
      runtime,
      AuthPolicyAction.CloseAccount,
      user.id,
      input.reAuthenticatedAt,
      now,
    )

    const revoked = await revokeUserSessions(runtime, {
      userId: user.id,
      now,
    })
    const closedUser = await runtime.repos.userRepo.update(user.id, {
      disabledAt: now,
      updatedAt: now,
    })

    await audit(runtime, AuditEventType.AccountClosed, now, {
      userId: user.id,
      sessionId: session.id,
      metadata: {
        revokedSessionIds: [...revoked.revokedSessionIds],
        ...optionalProp('requestMetadata', metadata),
      },
    })

    return {
      user: closedUser,
      currentSessionId: session.id,
      revokedSessionIds: revoked.revokedSessionIds,
    }
  })
}

export async function updateCurrentAccountProfileByToken(
  runtime: AuthServiceRuntime,
  input: UpdateCurrentAccountProfileByTokenInput,
): Promise<User> {
  return runtime.transaction.run(async () => {
    const now = input.now ?? runtime.clock.now()
    const metadata = normalizeCurrentAccountMetadata(input.metadata)
    const { session, user } = await resolveSessionContext(runtime, {
      sessionToken: input.sessionToken,
      now,
    })

    await ensureReAuth(
      runtime,
      AuthPolicyAction.UpdateProfile,
      user.id,
      input.reAuthenticatedAt,
      now,
    )

    const patch = normalizeCurrentAccountProfilePatch(input, now)
    const updated = await runtime.repos.userRepo.update(user.id, patch)

    await audit(runtime, AuditEventType.AccountProfileUpdated, now, {
      userId: user.id,
      sessionId: session.id,
      metadata: {
        changedFields: [CurrentAccountProfileField.DisplayName],
        ...optionalProp('requestMetadata', metadata),
      },
    })

    return updated
  })
}

export async function setCurrentAccountPasswordByToken(
  runtime: AuthServiceRuntime,
  input: SetCurrentAccountPasswordByTokenInput,
): Promise<Credential> {
  return runtime.transaction.run(async () => {
    const now = input.now ?? runtime.clock.now()
    const metadata = normalizeCurrentAccountMetadata(input.metadata)
    const { user } = await resolveSessionContext(runtime, {
      sessionToken: input.sessionToken,
      now,
    })
    const email = user.email?.trim()

    if (!email) {
      throw invalidInput('Password setup requires a trusted email address.')
    }

    return setPassword(runtime, {
      userId: user.id,
      email,
      password: input.password,
      ...optionalProp('reAuthenticatedAt', input.reAuthenticatedAt),
      now,
      ...optionalProp('metadata', metadata),
    })
  })
}

export async function changeCurrentAccountPasswordByToken(
  runtime: AuthServiceRuntime,
  input: ChangeCurrentAccountPasswordByTokenInput,
): Promise<Credential> {
  return runtime.transaction.run(async () => {
    const now = input.now ?? runtime.clock.now()
    const metadata = normalizeCurrentAccountMetadata(input.metadata)
    const { user } = await resolveSessionContext(runtime, {
      sessionToken: input.sessionToken,
      now,
    })

    return changePassword(runtime, {
      userId: user.id,
      currentPassword: input.currentPassword,
      newPassword: input.newPassword,
      ...optionalProp('reAuthenticatedAt', input.reAuthenticatedAt),
      now,
      ...optionalProp('metadata', metadata),
    })
  })
}

function normalizeCurrentAccountMetadata(
  metadata: Record<string, unknown> | undefined,
): Record<string, unknown> | undefined {
  return normalizeMetadataRecord(metadata, 'Current-account request metadata')
}

function normalizeCurrentAccountProfilePatch(
  input: UpdateCurrentAccountProfileByTokenInput,
  now: Date,
): Pick<User, 'updatedAt'> & { readonly displayName?: User['displayName'] | undefined } {
  if (!Object.hasOwn(input, CurrentAccountProfileField.DisplayName)) {
    throw invalidInput('Current account profile update requires at least one profile field.')
  }

  const displayName =
    typeof input.displayName === 'string' ? input.displayName.trim() || undefined : undefined

  return {
    displayName,
    updatedAt: now,
  }
}
