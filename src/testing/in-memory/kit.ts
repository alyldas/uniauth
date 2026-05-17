import {
  createAuthService,
  type DefaultAuthService,
  type DefaultAuthServiceOptions,
} from '../../application/auth-service.js'
import { optionalProp } from '../../application/optional.js'
import { invalidInput } from '../../errors.js'
import type { AuthPolicy } from '../../application/policy.js'
import type {
  AuthNormalizer,
  Clock,
  IdGenerator,
  OtpSecretGenerator,
  PasswordHasher,
  PasswordPolicy,
  RateLimiter,
  SecretHasher,
} from '../../contracts.js'
import { createSequentialIdGenerator } from '../../utils/ids.js'
import { createScryptSecretHasher } from '../../utils/secrets.js'
import { InMemoryProviderRegistry } from '../providers.js'
import { InMemoryEmailSender, InMemorySmsSender } from './senders.js'
import { InMemoryAuthStore } from './store.js'
import { InMemoryPasswordHasher, InMemoryRateLimiter } from './support.js'

const inMemorySecretHasher = createScryptSecretHasher({
  cost: 16,
  blockSize: 1,
  parallelization: 1,
  keyLength: 16,
  saltByteLength: 8,
  maxmem: 1024 * 1024,
})

export interface CreateInMemoryAuthKitOptions {
  readonly policy?: AuthPolicy
  readonly clock?: Clock
  readonly idGenerator?: IdGenerator
  readonly normalizer?: AuthNormalizer
  readonly secretHasher?: SecretHasher
  readonly rateLimiter?: RateLimiter
  readonly otpSecretLength?: number
  readonly otpSecretGenerator?: OtpSecretGenerator
  readonly emailOtpSubject?: string
  readonly passwordHasher?: PasswordHasher
  readonly passwordPolicy?: PasswordPolicy
  readonly sessionTtlSeconds?: number
  readonly verificationTtlSeconds?: number
  readonly verificationResendCooldownSeconds?: number
}

interface InMemoryAuthKitResult {
  readonly service: DefaultAuthService
  readonly store: InMemoryAuthStore
  readonly providerRegistry: InMemoryProviderRegistry
  readonly emailSender: InMemoryEmailSender
  readonly smsSender: InMemorySmsSender
  readonly rateLimiter: RateLimiter
  readonly passwordHasher: PasswordHasher
  readonly idGenerator: IdGenerator
}

export function createInMemoryAuthKit(
  options: CreateInMemoryAuthKitOptions = {},
): InMemoryAuthKitResult {
  if (!isOptionsRecord(options)) {
    throw invalidInput('In-memory auth kit options must be a plain object.')
  }

  const store = new InMemoryAuthStore({
    ...optionalProp('normalizer', options.normalizer),
  })
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
    secretHasher: options.secretHasher ?? inMemorySecretHasher,
    ...optionalProp('normalizer', options.normalizer),
    ...optionalProp('policy', options.policy),
    ...optionalProp('clock', options.clock),
    ...optionalProp('otpSecretLength', options.otpSecretLength),
    ...optionalProp('otpSecretGenerator', options.otpSecretGenerator),
    ...optionalProp('emailOtpSubject', options.emailOtpSubject),
    ...optionalProp('passwordPolicy', options.passwordPolicy),
    ...optionalProp('sessionTtlSeconds', options.sessionTtlSeconds),
    ...optionalProp('verificationTtlSeconds', options.verificationTtlSeconds),
    ...optionalProp('verificationResendCooldownSeconds', options.verificationResendCooldownSeconds),
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

function isOptionsRecord(value: unknown): value is CreateInMemoryAuthKitOptions {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    return false
  }

  const prototype = Object.getPrototypeOf(value)
  return prototype === Object.prototype || prototype === null
}
