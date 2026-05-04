import { optionalProp } from './optional.js'
import type { AuthPolicy } from './policy.js'
import { defaultAuthPolicy } from './policy.js'
import type { AuthServiceRuntime } from './runtime.js'
import type {
  AuthServiceInfrastructure,
  AuthServiceRepositories,
  Clock,
  IdGenerator,
  ProviderRegistry,
  UnitOfWork,
} from '../contracts.js'
import { createRandomIdGenerator } from '../utils/ids.js'
import { compatibilityAuthNormalizer } from '../utils/normalization.js'
import { scryptSecretHasher } from '../utils/secrets.js'
import { systemClock } from '../utils/time.js'

const DEFAULT_SESSION_TTL_SECONDS = 60 * 60 * 24 * 30
const DEFAULT_VERIFICATION_TTL_SECONDS = 60 * 10
const DEFAULT_VERIFICATION_RESEND_COOLDOWN_SECONDS = 0

const immediateUnitOfWork: UnitOfWork = {
  run: (operation) => operation(),
}

export interface DefaultAuthServiceOptions extends AuthServiceInfrastructure {
  readonly repos: AuthServiceRepositories
  readonly policy?: AuthPolicy
  readonly providerRegistry?: ProviderRegistry | undefined
  readonly transaction?: UnitOfWork
  readonly idGenerator?: IdGenerator
  readonly clock?: Clock
  readonly sessionTtlSeconds?: number
  readonly verificationTtlSeconds?: number
  readonly verificationResendCooldownSeconds?: number
}

export function createAuthServiceRuntime(options: DefaultAuthServiceOptions): AuthServiceRuntime {
  return {
    repos: options.repos,
    ...optionalProp('emailSender', options.emailSender),
    ...optionalProp('smsSender', options.smsSender),
    ...optionalProp('rateLimiter', options.rateLimiter),
    verificationResendCooldownSeconds:
      options.verificationResendCooldownSeconds ?? DEFAULT_VERIFICATION_RESEND_COOLDOWN_SECONDS,
    ...optionalProp('otpSecretLength', options.otpSecretLength),
    ...optionalProp('otpSecretGenerator', options.otpSecretGenerator),
    ...optionalProp('emailOtpSubject', options.emailOtpSubject),
    ...optionalProp('passwordHasher', options.passwordHasher),
    policy: options.policy ?? defaultAuthPolicy,
    providerRegistry: options.providerRegistry,
    transaction: options.transaction ?? immediateUnitOfWork,
    idGenerator: options.idGenerator ?? createRandomIdGenerator(),
    normalizer: options.normalizer ?? compatibilityAuthNormalizer,
    secretHasher: options.secretHasher ?? scryptSecretHasher,
    clock: options.clock ?? systemClock,
    sessionTtlSeconds: options.sessionTtlSeconds ?? DEFAULT_SESSION_TTL_SECONDS,
    verificationTtlSeconds: options.verificationTtlSeconds ?? DEFAULT_VERIFICATION_TTL_SECONDS,
  }
}
