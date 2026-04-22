import { createHash, createHmac, randomBytes, randomInt, timingSafeEqual } from 'node:crypto'

const SECRET_HASH_PREFIX = 'sha256:'
const HMAC_SECRET_HASH_PREFIX = 'hmac-sha256:'

export interface SecretHasher {
  hash(secret: string): string | Promise<string>
  verify(secret: string, secretHash: string): boolean | Promise<boolean>
}

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
  return verifyPrefixedSecret(secretHash, hashSecret(secret), SECRET_HASH_PREFIX)
}

export const sha256SecretHasher: SecretHasher = {
  hash: hashSecret,
  verify: verifySecret,
}

export function createHmacSecretHasher(input: { readonly pepper: string }): SecretHasher {
  if (!input.pepper) {
    throw new Error('Secret hasher pepper is required.')
  }

  const hash = (secret: string): string =>
    `${HMAC_SECRET_HASH_PREFIX}${createHmac('sha256', input.pepper).update(secret).digest('hex')}`

  return {
    hash,
    verify(secret, secretHash): boolean {
      return verifyPrefixedSecret(secretHash, hash(secret), HMAC_SECRET_HASH_PREFIX)
    },
  }
}

function verifyPrefixedSecret(secretHash: string, actualHash: string, prefix: string): boolean {
  if (!secretHash.startsWith(prefix)) {
    return false
  }

  const expected = Buffer.from(secretHash)
  const actual = Buffer.from(actualHash)

  if (actual.length !== expected.length) {
    return false
  }

  return timingSafeEqual(actual, expected)
}
