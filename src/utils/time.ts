import type { Clock } from '../contracts.js'
import { invalidInput } from '../errors.js'

export const systemClock: Clock = {
  now: () => new Date(),
}

export function addSeconds(date: Date, seconds: number): Date {
  return new Date(date.getTime() + seconds * 1000)
}

export function assertValidDate(date: Date, message: string): void {
  if (Number.isNaN(date.getTime())) {
    throw invalidInput(message)
  }
}
