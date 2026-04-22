export function normalizeEmail(email: string): string {
  return email.trim().toLowerCase()
}

export function normalizePhone(phone: string): string {
  return phone.replace(/[\s().-]+/g, '').trim()
}

export function normalizeTarget(target: string): string {
  const trimmed = target.trim()

  if (trimmed.includes('@')) {
    return normalizeEmail(trimmed)
  }

  return normalizePhone(trimmed)
}
