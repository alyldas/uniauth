import type { Clock } from '../contracts.js'
import { invalidInput } from '../errors.js'

export const systemClock: Clock = {
  now: () => new Date(),
}

export function addSeconds(date: Date, seconds: number): Date {
  assertValidDate(date, 'Date must be valid.')

  if (typeof seconds !== 'number' || !Number.isFinite(seconds)) {
    throw invalidInput('Seconds must be a finite number.')
  }

  return new Date(date.getTime() + seconds * 1000)
}

export function assertValidDate(date: unknown, message: string): asserts date is Date {
  if (!(date instanceof Date) || Number.isNaN(date.getTime())) {
    throw invalidInput(message)
  }
}
