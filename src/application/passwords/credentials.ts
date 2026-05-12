import { optionalProp } from '../optional.js'
import { normalizeMetadataRecord } from '../metadata.js'
import { AuthPolicyAction } from '../policy.js'
import type { AuthServiceRuntime } from '../runtime.js'
import { ensureReAuth, getActiveUser } from '../support.js'
import {
  CredentialType,
  type ChangePasswordInput,
  type Credential,
  type SetPasswordInput,
} from '../../domain/types.js'
import { UniAuthError, UniAuthErrorCode, invalidCredentials, invalidInput } from '../../errors.js'
import {
  assertPassword,
  ensurePasswordIdentity,
  findUsablePasswordIdentity,
  getPasswordHasher,
  normalizePasswordEmail,
} from './shared.js'

export async function setPassword(
  runtime: AuthServiceRuntime,
  input: SetPasswordInput,
): Promise<Credential> {
  return runtime.transaction.run(async () => {
    const now = input.now ?? runtime.clock.now()
    const metadata = normalizePasswordMetadata(input.metadata)
    const user = await getActiveUser(runtime, input.userId)
    await ensureReAuth(runtime, AuthPolicyAction.SetPassword, user.id, input.reAuthenticatedAt, now)

    const email = normalizePasswordEmail(runtime, input.email)
    assertPassword(input.password)
    const passwordHasher = getPasswordHasher(runtime)
    const existingForEmail = await runtime.repos.credentialRepo.findPasswordByEmail(email)

    if (existingForEmail && existingForEmail.userId !== user.id) {
      throw new UniAuthError(UniAuthErrorCode.CredentialAlreadyExists, 'Credential already exists.')
    }

    const existingForUser = await runtime.repos.credentialRepo.findPasswordByUserId(user.id)

    if (existingForUser && existingForUser.subject !== email) {
      throw invalidInput('Password credential email cannot be changed.')
    }

    const passwordHash = await passwordHasher.hash(input.password)
    await ensurePasswordIdentity(runtime, user, email, now)

    if (existingForUser) {
      return runtime.repos.credentialRepo.update(existingForUser.id, {
        passwordHash,
        updatedAt: now,
        ...optionalProp('metadata', metadata),
      })
    }

    return runtime.repos.credentialRepo.create({
      id: runtime.idGenerator.credentialId(),
      userId: user.id,
      type: CredentialType.Password,
      subject: email,
      passwordHash,
      createdAt: now,
      updatedAt: now,
      ...optionalProp('metadata', metadata),
    })
  })
}

export async function changePassword(
  runtime: AuthServiceRuntime,
  input: ChangePasswordInput,
): Promise<Credential> {
  return runtime.transaction.run(async () => {
    const now = input.now ?? runtime.clock.now()
    const metadata = normalizePasswordMetadata(input.metadata)
    const user = await getActiveUser(runtime, input.userId)
    await ensureReAuth(
      runtime,
      AuthPolicyAction.ChangePassword,
      user.id,
      input.reAuthenticatedAt,
      now,
    )

    assertPassword(input.newPassword)
    const passwordHasher = getPasswordHasher(runtime)
    const credential = await runtime.repos.credentialRepo.findPasswordByUserId(user.id)

    if (
      !credential ||
      !(await passwordHasher.verify(input.currentPassword, credential.passwordHash))
    ) {
      throw invalidCredentials()
    }

    await findUsablePasswordIdentity(runtime, credential, credential.subject)

    return runtime.repos.credentialRepo.update(credential.id, {
      passwordHash: await passwordHasher.hash(input.newPassword),
      updatedAt: now,
      ...optionalProp('metadata', metadata),
    })
  })
}

function normalizePasswordMetadata(
  metadata: Record<string, unknown> | undefined,
): Record<string, unknown> | undefined {
  return normalizeMetadataRecord(metadata, 'Password metadata')
}
