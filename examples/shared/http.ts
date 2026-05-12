import { UniAuthErrorCode, isUniAuthError } from '@alyldas/uniauth'

export const AUTHENTICATION_REQUIRED_MESSAGE = 'Authentication required.'
export const REQUEST_CANNOT_BE_COMPLETED_MESSAGE = 'Request cannot be completed.'
export const TOO_MANY_AUTH_ATTEMPTS_MESSAGE = 'Too many auth attempts.'

export function readBearerToken(header: string | undefined): string | undefined {
  if (!header) {
    return undefined
  }

  const parts = header.trim().split(/\s+/)

  if (parts.length !== 2) {
    return undefined
  }

  const scheme = parts[0]!
  const value = parts[1]!
  return scheme.toLowerCase() === 'bearer' && value ? value : undefined
}

export function readCookieHeaderToken(
  header: string | undefined,
  name: string,
): string | undefined {
  if (!header) {
    return undefined
  }

  for (const part of header.split(';')) {
    const [rawName, ...rest] = part.split('=')

    if (!rawName || rawName.trim() !== name) {
      continue
    }

    const value = rest.join('=').trim()

    if (!value) {
      return undefined
    }

    try {
      return decodeURIComponent(value)
    } catch {
      return undefined
    }
  }

  return undefined
}

export function readCookieValue(value: string | undefined): string | undefined {
  return value?.trim() || undefined
}

export function isSessionContextError(error: unknown): boolean {
  return (
    isUniAuthError(error) &&
    (error.code === UniAuthErrorCode.InvalidInput ||
      error.code === UniAuthErrorCode.SessionNotFound)
  )
}
