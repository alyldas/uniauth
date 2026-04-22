import { createHash, randomBytes, randomInt, timingSafeEqual } from 'node:crypto'

const SECRET_HASH_PREFIX = 'sha256:'

export function generateSecret(byteLength = 32): string {
  return randomBytes(byteLength).toString('base64url')
}

export function generateOtpSecret(length = 6): string {
  return Array.from({ length }, () => randomInt(10).toString()).join('')
}

export function hashSecret(secret: string): string {
  return `${SECRET_HASH_PREFIX}${createHash('sha256').update(secret).digest('hex')}`
}

export function verifySecret(secret: string, secretHash: string): boolean {
  if (!secretHash.startsWith(SECRET_HASH_PREFIX)) {
    return false
  }

  const expected = Buffer.from(secretHash)
  const actual = Buffer.from(hashSecret(secret))

  if (actual.length !== expected.length) {
    return false
  }

  return timingSafeEqual(actual, expected)
}
