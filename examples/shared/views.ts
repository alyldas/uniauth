import type { AccountSecuritySnapshot, VerificationStatusView } from '@alyldas/uniauth'

export function serializeAccountSecuritySnapshot(snapshot: AccountSecuritySnapshot) {
  return {
    user: {
      id: snapshot.user.id,
      email: snapshot.user.email ?? null,
      phone: snapshot.user.phone ?? null,
      displayName: snapshot.user.displayName ?? null,
      createdAt: snapshot.user.createdAt.toISOString(),
      updatedAt: snapshot.user.updatedAt.toISOString(),
      disabledAt: snapshot.user.disabledAt?.toISOString() ?? null,
    },
    identities: snapshot.identities.map((identity) => ({
      id: identity.id,
      provider: identity.provider,
      status: identity.status,
      email: identity.email ?? null,
      emailVerified: identity.emailVerified ?? null,
      phone: identity.phone ?? null,
      phoneVerified: identity.phoneVerified ?? null,
      trustLevel: identity.trustLevel ?? null,
      createdAt: identity.createdAt.toISOString(),
      updatedAt: identity.updatedAt.toISOString(),
      disabledAt: identity.disabledAt?.toISOString() ?? null,
    })),
    credentials: snapshot.credentials.map((credential) => ({
      id: credential.id,
      type: credential.type,
      subject: credential.subject,
      createdAt: credential.createdAt.toISOString(),
      updatedAt: credential.updatedAt.toISOString(),
    })),
    sessions: snapshot.sessions.map((session) => ({
      id: session.id,
      status: session.status,
      createdAt: session.createdAt.toISOString(),
      expiresAt: session.expiresAt.toISOString(),
      lastSeenAt: session.lastSeenAt?.toISOString() ?? null,
      revokedAt: session.revokedAt?.toISOString() ?? null,
    })),
  }
}

export function serializeVerificationStatusView(view: VerificationStatusView) {
  return {
    id: view.id,
    purpose: view.purpose,
    status: view.status,
    expiresAt: view.expiresAt.toISOString(),
    consumedAt: view.consumedAt?.toISOString() ?? null,
  }
}
