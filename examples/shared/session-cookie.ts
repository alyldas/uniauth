import { createCipheriv, createDecipheriv, createHash, randomBytes } from 'node:crypto'

const SESSION_COOKIE_KEY_ENV = 'UNIAUTH_EXAMPLE_SESSION_COOKIE_KEY'
const SESSION_COOKIE_SEAL_VERSION = 'v1'
const SESSION_COOKIE_CIPHER = 'aes-256-gcm'
const SESSION_COOKIE_IV_BYTES = 12
const SESSION_COOKIE_MIN_KEY_LENGTH = 32

export function sealSessionCookieValue(sessionToken: string): string {
  const iv = randomBytes(SESSION_COOKIE_IV_BYTES)
  const cipher = createCipheriv(SESSION_COOKIE_CIPHER, readSessionCookieKey(), iv)
  const encrypted = Buffer.concat([cipher.update(sessionToken, 'utf8'), cipher.final()])

  return [
    SESSION_COOKIE_SEAL_VERSION,
    iv.toString('base64url'),
    cipher.getAuthTag().toString('base64url'),
    encrypted.toString('base64url'),
  ].join('.')
}

export function unsealSessionCookieValue(value: string | undefined): string | undefined {
  const sealedValue = value?.trim()

  if (!sealedValue) {
    return undefined
  }

  const [version, ivRaw, tagRaw, encryptedRaw, extra] = sealedValue.split('.')

  if (
    version !== SESSION_COOKIE_SEAL_VERSION ||
    !ivRaw ||
    !tagRaw ||
    !encryptedRaw ||
    extra !== undefined
  ) {
    return undefined
  }

  try {
    const decipher = createDecipheriv(
      SESSION_COOKIE_CIPHER,
      readSessionCookieKey(),
      Buffer.from(ivRaw, 'base64url'),
    )
    decipher.setAuthTag(Buffer.from(tagRaw, 'base64url'))

    const decrypted = Buffer.concat([
      decipher.update(Buffer.from(encryptedRaw, 'base64url')),
      decipher.final(),
    ]).toString('utf8')

    return decrypted || undefined
  } catch {
    return undefined
  }
}

export function assertSessionCookieSealingConfigured(): void {
  void readSessionCookieKey()
}

function readSessionCookieKey(): Buffer {
  const keyMaterial = process.env[SESSION_COOKIE_KEY_ENV]?.trim()

  if (!keyMaterial || keyMaterial.length < SESSION_COOKIE_MIN_KEY_LENGTH) {
    throw new Error(
      `${SESSION_COOKIE_KEY_ENV} must contain at least ${SESSION_COOKIE_MIN_KEY_LENGTH} random characters.`,
    )
  }

  return createHash('sha256').update(keyMaterial).digest()
}
