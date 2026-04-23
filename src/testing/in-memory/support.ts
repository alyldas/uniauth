import type {
  PasswordHasher,
  RateLimitAttempt,
  RateLimitDecision,
  RateLimiter,
} from '../../ports.js'
import { hashSecret } from '../../utils/secrets.js'

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
    return `test-password:${hashSecret(password)}`
  }

  async verify(password: string, passwordHash: string): Promise<boolean> {
    return passwordHash === (await this.hash(password))
  }
}
