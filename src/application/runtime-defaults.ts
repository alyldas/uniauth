import { optionalProp } from './optional.js'
import type { AuthPolicy } from './policy.js'
import { defaultAuthPolicy } from './policy.js'
import type { AuthServiceRuntime } from './runtime.js'
import { invalidInput } from '../errors.js'
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
  if (!isRecord(options)) {
    throw invalidInput('Auth service options must be a plain object.')
  }

  assertRepositories(options.repos)

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
    transaction:
      options.transaction ?? getRepositoryUnitOfWork(options.repos) ?? immediateUnitOfWork,
    idGenerator: options.idGenerator ?? createRandomIdGenerator(),
    normalizer: options.normalizer ?? compatibilityAuthNormalizer,
    secretHasher: options.secretHasher ?? scryptSecretHasher,
    clock: options.clock ?? systemClock,
    sessionTtlSeconds: options.sessionTtlSeconds ?? DEFAULT_SESSION_TTL_SECONDS,
    verificationTtlSeconds: options.verificationTtlSeconds ?? DEFAULT_VERIFICATION_TTL_SECONDS,
  }
}

function getRepositoryUnitOfWork(repos: AuthServiceRepositories): UnitOfWork | undefined {
  const candidate = repos as Partial<UnitOfWork>
  return typeof candidate.run === 'function'
    ? { run: (operation) => candidate.run!(operation) }
    : undefined
}

function assertRepositories(repos: unknown): asserts repos is AuthServiceRepositories {
  if (!isRecord(repos)) {
    throw invalidInput('Auth service repositories are required.')
  }

  assertRepo(repos.userRepo, ['findById', 'create', 'update'], 'User repository')
  assertRepo(
    repos.identityRepo,
    [
      'findById',
      'findByProviderUserId',
      'findByVerifiedEmail',
      'findByVerifiedPhone',
      'listByUserId',
      'create',
      'update',
    ],
    'Identity repository',
  )
  assertRepo(
    repos.credentialRepo,
    ['findPasswordByEmail', 'findPasswordByUserId', 'listByUserId', 'create', 'update'],
    'Credential repository',
  )
  assertRepo(
    repos.verificationRepo,
    ['findById', 'findByIdForUpdate', 'create', 'update'],
    'Verification repository',
  )
  assertRepo(
    repos.sessionRepo,
    ['findById', 'findByTokenHash', 'listByUserId', 'create', 'update'],
    'Session repository',
  )
  assertRepo(repos.auditLogRepo, ['append', 'list'], 'Audit log repository')
}

function assertRepo(value: unknown, methods: readonly string[], name: string): void {
  if (!isRecord(value)) {
    throw invalidInput(`${name} is required.`)
  }

  for (const method of methods) {
    if (typeof value[method] !== 'function') {
      throw invalidInput(`${name} ${method} is required.`)
    }
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    return false
  }

  const prototype = Object.getPrototypeOf(value)
  return prototype === Object.prototype || prototype === null
}
