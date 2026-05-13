import type {
  PasswordHasher,
  RateLimitAttempt,
  RateLimitDecision,
  RateLimiter,
} from '../../contracts.js'
import { createScryptSecretHasher } from '../../utils/secrets.js'

const TEST_PASSWORD_HASH_PREFIX = 'test-password:'
const testPasswordScryptHasher = createScryptSecretHasher({
  cost: 16,
  blockSize: 1,
  parallelization: 1,
  keyLength: 16,
  saltByteLength: 8,
  maxmem: 1024 * 1024,
})

export class InMemoryRateLimiter implements RateLimiter {
  private readonly attempts: RateLimitAttempt[] = []
  private readonly decisions = new Map<string, RateLimitDecision>()

  async consume(input: RateLimitAttempt): Promise<RateLimitDecision> {
    this.attempts.push(input)
    return this.decisions.get(this.decisionKey(input.action, input.key)) ?? { allowed: true }
  }

  setDecision(input: Pick<RateLimitAttempt, 'action' | 'key'>, decision: RateLimitDecision): void {
    this.decisions.set(this.decisionKey(input.action, input.key), decision)
  }

  listAttempts(): readonly RateLimitAttempt[] {
    return [...this.attempts]
  }

  private decisionKey(action: RateLimitAttempt['action'], key: string): string {
    return `${action}\u0000${key}`
  }
}

export class InMemoryPasswordHasher implements PasswordHasher {
  async hash(password: string): Promise<string> {
    return `${TEST_PASSWORD_HASH_PREFIX}${await testPasswordScryptHasher.hash(password)}`
  }

  async verify(password: string, passwordHash: string): Promise<boolean> {
    if (typeof password !== 'string' || typeof passwordHash !== 'string') {
      return false
    }

    if (!passwordHash.startsWith(TEST_PASSWORD_HASH_PREFIX)) {
      return false
    }

    return await testPasswordScryptHasher.verify(
      password,
      passwordHash.slice(TEST_PASSWORD_HASH_PREFIX.length),
    )
  }
}
