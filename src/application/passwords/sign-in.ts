import { optionalProp } from '../optional.js'
import type { AuthServiceRuntime } from '../runtime.js'
import { createSessionRecord } from '../sessions.js'
import { audit, enforceRateLimit } from '../support.js'
import {
  AuditEventType,
  OtpChannel,
  PASSWORD_PROVIDER_ID,
  type AuthResult,
  type SignInWithPasswordInput,
} from '../../domain/types.js'
import { invalidCredentials } from '../../errors.js'
import { RateLimitAction, rateLimitKey } from '../../ports.js'
import {
  PasswordAuditMode,
  findPasswordCredentialByEmail,
  findUsableCredentialUser,
  findUsablePasswordIdentity,
  getPasswordHasher,
  normalizePasswordEmail,
} from './shared.js'

export async function signInWithPassword(
  runtime: AuthServiceRuntime,
  input: SignInWithPasswordInput,
): Promise<AuthResult> {
  const now = input.now ?? runtime.clock.now()
  const email = normalizePasswordEmail(runtime, input.email)
  if (typeof input.password !== 'string' || !input.password) {
    throw invalidCredentials()
  }

  const passwordHasher = getPasswordHasher(runtime)

  await enforceRateLimit(runtime, {
    action: RateLimitAction.PasswordSignIn,
    key: rateLimitKey(OtpChannel.Email, email),
    now,
    metadata: { provider: PASSWORD_PROVIDER_ID },
  })

  return runtime.transaction.run(async () => {
    const credential = await findPasswordCredentialByEmail(runtime, email)
    const identity = await findUsablePasswordIdentity(runtime, credential, email)

    if (!(await passwordHasher.verify(input.password, credential.passwordHash))) {
      throw invalidCredentials()
    }

    const user = await findUsableCredentialUser(runtime, credential)
    const createdSession = await createSessionRecord(runtime, {
      userId: user.id,
      now,
      ...optionalProp('expiresAt', input.sessionExpiresAt),
      ...optionalProp('metadata', input.metadata),
    })
    await audit(runtime, AuditEventType.SignIn, now, {
      userId: user.id,
      identityId: identity.id,
      sessionId: createdSession.session.id,
      metadata: { mode: PasswordAuditMode.Password },
    })

    return {
      user,
      identity,
      session: createdSession.session,
      sessionToken: createdSession.sessionToken,
      isNewUser: false,
      isNewIdentity: false,
    }
  })
}
