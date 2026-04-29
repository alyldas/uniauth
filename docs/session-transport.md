# Session Transport Recipes

UniAuth creates and revokes local session records. The application still owns how the one-time
`sessionToken` returned at session creation travels between client and server. `Session.id` is a
server-side record identifier, not a bearer credential.

This document keeps the boundary explicit for three common transports:

- browser cookies;
- API bearer transport;
- mobile or native client token storage.

## Browser Cookies

Browser-first applications usually map `result.sessionToken` into a session cookie immediately after
a successful finish flow.

Minimum expectations:

- `httpOnly: true`;
- `secure: true` in production;
- explicit `sameSite`;
- explicit `path`;
- separate cookie clearing on logout or revoke.

Example shape:

```ts
const result = await authService.finishOtpSignIn({
  verificationId: body.verificationId,
  secret: body.code,
})

response.cookie('session', result.sessionToken, {
  httpOnly: true,
  secure: true,
  sameSite: 'lax',
  path: '/',
})
```

On later requests, resolve the token through UniAuth instead of treating `Session.id` as the client
credential:

```ts
const session = await authService.resolveSession({
  sessionToken: request.cookies.session,
})
```

Applications that track recent activity can then explicitly update `lastSeenAt` through the public
service API:

```ts
await authService.touchSession({
  sessionId: session.id,
})
```

Keep this write policy application-owned. Touch on meaningful authenticated requests, not on every
asset fetch, health check, or background poll.

### Express Middleware Recipe

```ts
import type { NextFunction, Request, Response } from 'express'
import { UniAuthErrorCode, isUniAuthError, type AuthService, type Session } from '@alyldas/uniauth'

interface ExpressRequestAuth {
  readonly session: Session
  readonly userId: Session['userId']
}

declare global {
  namespace Express {
    interface Request {
      auth?: ExpressRequestAuth
    }
  }
}

export function createExpressSessionMiddleware(authService: AuthService) {
  return async (request: Request, response: Response, next: NextFunction): Promise<void> => {
    const sessionToken =
      readBearerToken(request.headers.authorization) ?? readCookieToken(request.headers.cookie)

    if (!sessionToken) {
      next()
      return
    }

    try {
      const resolved = await authService.resolveSession({ sessionToken })
      const session = await authService.touchSession({ sessionId: resolved.id })

      request.auth = {
        session,
        userId: session.userId,
      }
      next()
    } catch (error) {
      if (
        isUniAuthError(error) &&
        (error.code === UniAuthErrorCode.InvalidInput ||
          error.code === UniAuthErrorCode.SessionNotFound)
      ) {
        response.status(401).json({ error: 'Authentication required.' })
        return
      }

      next(error)
    }
  }
}

function readBearerToken(header: string | undefined): string | undefined {
  if (!header) {
    return undefined
  }

  const [scheme, value] = header.split(/\s+/, 2)
  return scheme?.toLowerCase() === 'bearer' && value?.trim() ? value.trim() : undefined
}

function readCookieToken(header: string | undefined): string | undefined {
  if (!header) {
    return undefined
  }

  for (const part of header.split(';')) {
    const [name, ...rest] = part.split('=')

    if (name.trim() !== 'session') {
      continue
    }

    const value = rest.join('=').trim()
    return value ? decodeURIComponent(value) : undefined
  }

  return undefined
}
```

Attach the middleware only where browser/API auth context is needed, or pair it with a small
`requireSession` guard for protected routes. If activity writes are too expensive for every request,
skip `touchSession(...)` here and call it only on the authenticated routes that matter.

### Fastify preHandler Recipe

```ts
import type { FastifyReply, FastifyRequest } from 'fastify'
import { UniAuthErrorCode, isUniAuthError, type AuthService, type Session } from '@alyldas/uniauth'

interface FastifyRequestAuth {
  readonly session: Session
  readonly userId: Session['userId']
}

declare module 'fastify' {
  interface FastifyRequest {
    auth?: FastifyRequestAuth
  }
}

export function createFastifySessionPreHandler(authService: AuthService) {
  return async (request: FastifyRequest, reply: FastifyReply): Promise<void> => {
    const sessionToken =
      readBearerToken(request.headers.authorization) ?? request.cookies.session?.trim()

    if (!sessionToken) {
      return
    }

    try {
      const resolved = await authService.resolveSession({ sessionToken })
      request.auth = {
        session: resolved,
        userId: resolved.userId,
      }
    } catch (error) {
      if (
        isUniAuthError(error) &&
        (error.code === UniAuthErrorCode.InvalidInput ||
          error.code === UniAuthErrorCode.SessionNotFound)
      ) {
        await reply.status(401).send({ error: 'Authentication required.' })
        return
      }

      throw error
    }
  }
}

function readBearerToken(header: string | undefined): string | undefined {
  if (!header) {
    return undefined
  }

  const [scheme, value] = header.split(/\s+/, 2)
  return scheme?.toLowerCase() === 'bearer' && value?.trim() ? value.trim() : undefined
}
```

Fastify users often keep `touchSession(...)` in a second protected-route hook or in the route
handler itself, so lightweight public requests can resolve auth context without forcing an activity
write every time.

What stays application-owned:

- CSRF protection for browser POST requests;
- domain and subdomain scoping;
- cookie signing or encryption policy;
- reverse-proxy HTTPS behavior;
- cookie clearing on logout.

## Bearer Transport

API-first applications may choose to return the local UniAuth `sessionToken` in the JSON response
and then send it back in an `Authorization` header or another app-owned header.

Example shape:

```ts
const result = await authService.signInWithPassword({
  email: body.email,
  password: body.password,
})

return {
  sessionToken: result.sessionToken,
  userId: result.user.id,
}
```

What stays application-owned:

- TLS-only transport;
- token forwarding rules between services;
- gateway or edge header normalization;
- server middleware that resolves the session token back into application auth context;
- the policy for when a resolved session should also be touched for activity tracking;
- log redaction so bearer session tokens do not leak into access logs.

## Mobile And Native Clients

Mobile or native applications often keep the local session token in platform-owned secure storage
instead of browser cookies.

Recommended boundary:

1. UniAuth returns a one-time local session token.
2. The API returns it to the client over TLS.
3. The client stores it in Keychain, Keystore, or another secure app-owned store.
4. Future API calls send that session token through an app-owned header or bearer transport.

What stays application-owned:

- secure storage choice;
- app logout UX;
- biometric gating before reuse;
- device binding, if required;
- session refresh or re-issuance policy.

## Logout And Revocation

UniAuth revokes the local session record, but it does not clear browser cookies or client storage.

Treat logout as two coordinated steps:

1. resolve the client token to a server session and call `authService.revokeSession(session.id)`;
2. remove the transport artifact:
   - clear the cookie;
   - delete the bearer token from client state;
   - delete the mobile-stored session token.

For sign-out-all-devices or device-management screens, applications can first call
`authService.getUserSessions(userId)` and then revoke the active subset through
`authService.revokeUserSessions({ userId, exceptSessionId })`. UniAuth still does not clear cookies
or bearer stores for those clients; the application must remove the transport artifact on each
device as it becomes aware of the revoked local session.

## Security Notes

- Session transport is not part of the package public API surface; it is deployment policy.
- Do not mix browser cookie assumptions into mobile or API bearer flows.
- Keep CSRF analysis only for cookie-based browser flows.
- Keep replay and theft analysis for bearer-like transports in the application threat model.

See also:

- [Backend integration recipes](backend-recipes.md)
- [Express auth module example](../examples/express-auth/index.ts)
- [Fastify auth module example](../examples/fastify-auth/index.ts)
- [Local auth flows](local-auth.md)
- [Security model](security.md)
- [Threat model](threat-model.md)
