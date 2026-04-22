import type { Clock } from '../domain/types.js'

export const systemClock: Clock = {
  now: () => new Date(),
}

export function addSeconds(date: Date, seconds: number): Date {
  return new Date(date.getTime() + seconds * 1000)
}
