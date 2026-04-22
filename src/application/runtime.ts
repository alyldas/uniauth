import type { DefaultAuthServiceOptions } from './auth-service.js'
import { optionalProp } from './optional.js'
import type { AuthPolicy } from './policy.js'
import { defaultAuthPolicy } from './policy.js'
import type { Clock, IdGenerator } from '../domain/types.js'
import type {
  AuthServiceInfrastructure,
  AuthServiceRepositories,
  ProviderRegistry,
  UnitOfWork,
} from '../ports.js'
import { createRandomIdGenerator } from '../utils/ids.js'
import { sha256SecretHasher, type SecretHasher } from '../utils/secrets.js'
import { systemClock } from '../utils/time.js'

const DEFAULT_SESSION_TTL_SECONDS = 60 * 60 * 24 * 30
const DEFAULT_VERIFICATION_TTL_SECONDS = 60 * 10

const immediateUnitOfWork: UnitOfWork = {
  run: (operation) => operation(),
}

export interface AuthServiceRuntime extends AuthServiceInfrastructure {
  readonly repos: AuthServiceRepositories
  readonly policy: AuthPolicy
  readonly providerRegistry: ProviderRegistry | undefined
  readonly transaction: UnitOfWork
  readonly idGenerator: IdGenerator
  readonly secretHasher: SecretHasher
  readonly clock: Clock
  readonly sessionTtlSeconds: number
  readonly verificationTtlSeconds: number
}

export function createAuthServiceRuntime(options: DefaultAuthServiceOptions): AuthServiceRuntime {
  return {
    repos: options.repos,
    ...optionalProp('emailSender', options.emailSender),
    ...optionalProp('smsSender', options.smsSender),
    policy: options.policy ?? defaultAuthPolicy,
    providerRegistry: options.providerRegistry,
    transaction: options.transaction ?? immediateUnitOfWork,
    idGenerator: options.idGenerator ?? createRandomIdGenerator(),
    secretHasher: options.secretHasher ?? sha256SecretHasher,
    clock: options.clock ?? systemClock,
    sessionTtlSeconds: options.sessionTtlSeconds ?? DEFAULT_SESSION_TTL_SECONDS,
    verificationTtlSeconds: options.verificationTtlSeconds ?? DEFAULT_VERIFICATION_TTL_SECONDS,
  }
}
