import {
  createAuthService,
  type DefaultAuthService,
  type DefaultAuthServiceOptions,
} from '../../application/auth-service.js'
import { optionalProp } from '../../application/optional.js'
import type { AuthPolicy } from '../../application/policy.js'
import type { Clock, IdGenerator } from '../../domain/types.js'
import type { OtpSecretGenerator, PasswordHasher, RateLimiter } from '../../ports.js'
import { createSequentialIdGenerator } from '../../utils/ids.js'
import type { SecretHasher } from '../../utils/secrets.js'
import { InMemoryProviderRegistry } from '../providers.js'
import { InMemoryEmailSender, InMemorySmsSender } from './senders.js'
import { InMemoryAuthStore } from './store.js'
import { InMemoryPasswordHasher, InMemoryRateLimiter } from './support.js'

export interface CreateInMemoryAuthKitOptions {
  readonly policy?: AuthPolicy
  readonly clock?: Clock
  readonly idGenerator?: IdGenerator
  readonly secretHasher?: SecretHasher
  readonly rateLimiter?: RateLimiter
  readonly otpSecretLength?: number
  readonly otpSecretGenerator?: OtpSecretGenerator
  readonly emailOtpSubject?: string
  readonly passwordHasher?: PasswordHasher
  readonly sessionTtlSeconds?: number
  readonly verificationTtlSeconds?: number
}

export interface InMemoryAuthKit {
  readonly service: DefaultAuthService
  readonly store: InMemoryAuthStore
  readonly providerRegistry: InMemoryProviderRegistry
  readonly emailSender: InMemoryEmailSender
  readonly smsSender: InMemorySmsSender
  readonly rateLimiter: RateLimiter
  readonly passwordHasher: PasswordHasher
  readonly idGenerator: IdGenerator
}

export function createInMemoryAuthKit(options: CreateInMemoryAuthKitOptions = {}): InMemoryAuthKit {
  const store = new InMemoryAuthStore()
  const providerRegistry = new InMemoryProviderRegistry()
  const emailSender = new InMemoryEmailSender()
  const smsSender = new InMemorySmsSender()
  const rateLimiter = options.rateLimiter ?? new InMemoryRateLimiter()
  const passwordHasher = options.passwordHasher ?? new InMemoryPasswordHasher()
  const idGenerator = options.idGenerator ?? createSequentialIdGenerator()
  const serviceOptions: DefaultAuthServiceOptions = {
    repos: store,
    emailSender,
    smsSender,
    rateLimiter,
    passwordHasher,
    providerRegistry,
    transaction: store,
    idGenerator,
    ...optionalProp('secretHasher', options.secretHasher),
    ...optionalProp('policy', options.policy),
    ...optionalProp('clock', options.clock),
    ...optionalProp('otpSecretLength', options.otpSecretLength),
    ...optionalProp('otpSecretGenerator', options.otpSecretGenerator),
    ...optionalProp('emailOtpSubject', options.emailOtpSubject),
    ...optionalProp('sessionTtlSeconds', options.sessionTtlSeconds),
    ...optionalProp('verificationTtlSeconds', options.verificationTtlSeconds),
  }

  return {
    service: createAuthService(serviceOptions),
    store,
    providerRegistry,
    emailSender,
    smsSender,
    rateLimiter,
    passwordHasher,
    idGenerator,
  }
}
