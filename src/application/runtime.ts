import type { AuthPolicy } from './policy.js'
import type {
  AuthNormalizer,
  AuthServiceInfrastructure,
  AuthServiceRepositories,
  Clock,
  IdGenerator,
  ProviderRegistry,
  SecretHasher,
  UnitOfWork,
} from '../contracts.js'

export interface AuthServiceRuntime extends AuthServiceInfrastructure {
  readonly repos: AuthServiceRepositories
  readonly policy: AuthPolicy
  readonly providerRegistry: ProviderRegistry | undefined
  readonly transaction: UnitOfWork
  readonly idGenerator: IdGenerator
  readonly normalizer: AuthNormalizer
  readonly secretHasher: SecretHasher
  readonly clock: Clock
  readonly sessionTtlSeconds: number
  readonly verificationTtlSeconds: number
  readonly verificationResendCooldownSeconds: number
}
