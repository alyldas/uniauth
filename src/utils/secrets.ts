import {
  createHash,
  createHmac,
  randomBytes,
  randomInt,
  scrypt as scryptCallback,
  timingSafeEqual,
  type ScryptOptions,
} from 'node:crypto'
import { promisify } from 'node:util'
import type { ScryptSecretHasherOptions, SecretHasher } from '../contracts.js'
export type { ScryptSecretHasherOptions, SecretHasher } from '../contracts.js'

const SECRET_HASH_PREFIX = 'sha256:'
const HMAC_SECRET_HASH_PREFIX = 'hmac-sha256:'
const SCRYPT_SECRET_HASH_PREFIX = 'scrypt:'
const DEFAULT_SCRYPT_COST = 16_384
const DEFAULT_SCRYPT_BLOCK_SIZE = 8
const DEFAULT_SCRYPT_PARALLELIZATION = 1
const DEFAULT_SCRYPT_KEY_LENGTH = 32
const DEFAULT_SCRYPT_SALT_BYTE_LENGTH = 16
const DEFAULT_SCRYPT_MAXMEM = 64 * 1024 * 1024
const scryptAsync = promisify(
  scryptCallback as (
    password: string,
    salt: Buffer,
    keylen: number,
    options: ScryptOptions,
    callback: (error: Error | null, derivedKey: Buffer) => void,
  ) => void,
)

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

export function createScryptSecretHasher(options: ScryptSecretHasherOptions = {}): SecretHasher {
  const cost = readPositiveInteger(options.cost ?? DEFAULT_SCRYPT_COST, 'Scrypt cost')
  const blockSize = readPositiveInteger(
    options.blockSize ?? DEFAULT_SCRYPT_BLOCK_SIZE,
    'Scrypt block size',
  )
  const parallelization = readPositiveInteger(
    options.parallelization ?? DEFAULT_SCRYPT_PARALLELIZATION,
    'Scrypt parallelization',
  )
  const keyLength = readPositiveInteger(
    options.keyLength ?? DEFAULT_SCRYPT_KEY_LENGTH,
    'Scrypt key length',
  )
  const saltByteLength = readPositiveInteger(
    options.saltByteLength ?? DEFAULT_SCRYPT_SALT_BYTE_LENGTH,
    'Scrypt salt byte length',
  )
  const maxmem = readPositiveInteger(options.maxmem ?? DEFAULT_SCRYPT_MAXMEM, 'Scrypt maxmem')

  if ((cost & (cost - 1)) !== 0) {
    throw new Error('Scrypt cost must be a power of two.')
  }

  return {
    async hash(secret): Promise<string> {
      const salt = randomBytes(saltByteLength)
      const derived = await deriveScrypt(secret, salt, {
        cost,
        blockSize,
        parallelization,
        keyLength,
        maxmem,
      })

      return [
        SCRYPT_SECRET_HASH_PREFIX.slice(0, -1),
        cost,
        blockSize,
        parallelization,
        keyLength,
        salt.toString('base64url'),
        derived.toString('base64url'),
      ].join(':')
    },
    async verify(secret, secretHash): Promise<boolean> {
      return verifyScryptSecret(secret, secretHash)
    },
  }
}

export const scryptSecretHasher: SecretHasher = createScryptSecretHasher()

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

async function verifyScryptSecret(secret: string, secretHash: string): Promise<boolean> {
  if (!secretHash.startsWith(SCRYPT_SECRET_HASH_PREFIX)) {
    return false
  }

  const [, costRaw, blockSizeRaw, parallelizationRaw, keyLengthRaw, saltRaw, expectedRaw] =
    secretHash.split(':')

  if (
    !costRaw ||
    !blockSizeRaw ||
    !parallelizationRaw ||
    !keyLengthRaw ||
    !saltRaw ||
    !expectedRaw
  ) {
    return false
  }

  const cost = Number(costRaw)
  const blockSize = Number(blockSizeRaw)
  const parallelization = Number(parallelizationRaw)
  const keyLength = Number(keyLengthRaw)

  if (
    !Number.isInteger(cost) ||
    !Number.isInteger(blockSize) ||
    !Number.isInteger(parallelization) ||
    !Number.isInteger(keyLength) ||
    cost <= 0 ||
    blockSize <= 0 ||
    parallelization <= 0 ||
    keyLength <= 0
  ) {
    return false
  }

  try {
    const salt = Buffer.from(saltRaw, 'base64url')
    const expected = Buffer.from(expectedRaw, 'base64url')
    const actual = await deriveScrypt(secret, salt, {
      cost,
      blockSize,
      parallelization,
      keyLength,
      maxmem: DEFAULT_SCRYPT_MAXMEM,
    })

    if (actual.length !== expected.length) {
      return false
    }

    return timingSafeEqual(actual, expected)
  } catch {
    return false
  }
}

async function deriveScrypt(
  secret: string,
  salt: Buffer,
  options: {
    readonly cost: number
    readonly blockSize: number
    readonly parallelization: number
    readonly keyLength: number
    readonly maxmem: number
  },
): Promise<Buffer> {
  const derivedKey = await scryptAsync(secret, salt, options.keyLength, {
    N: options.cost,
    r: options.blockSize,
    p: options.parallelization,
    maxmem: options.maxmem,
  })

  return Buffer.from(derivedKey)
}

function readPositiveInteger(value: number, name: string): number {
  if (!Number.isInteger(value) || value <= 0) {
    throw new Error(`${name} must be a positive integer.`)
  }

  return value
}
