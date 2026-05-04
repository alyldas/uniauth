import type { AuthNormalizer, SecretHasher } from '../contracts.js'
import type { EmailSender, SmsSender } from './messaging.js'
import type { ProviderRegistry } from './providers.js'
import type { AuthServiceRepositories } from './repositories.js'
import type { OtpSecretGenerator, RateLimiter } from './rate-limit.js'
import type { PasswordHasher } from './security.js'

export interface AuthServiceInfrastructure {
  readonly emailSender?: EmailSender
  readonly smsSender?: SmsSender
  readonly normalizer?: AuthNormalizer
  readonly secretHasher?: SecretHasher
  readonly rateLimiter?: RateLimiter
  readonly verificationResendCooldownSeconds?: number
  readonly otpSecretLength?: number
  readonly otpSecretGenerator?: OtpSecretGenerator
  readonly emailOtpSubject?: string
  readonly passwordHasher?: PasswordHasher
}

export interface UnitOfWork {
  run<T>(operation: () => Promise<T>): Promise<T>
}

export type {
  AuthServiceRepositories,
  EmailSender,
  PasswordHasher,
  ProviderRegistry,
  RateLimiter,
  SmsSender,
}
