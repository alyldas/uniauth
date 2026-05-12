# Backend Integration Recipes

UniAuth stays headless across all backend frameworks. The framework owns HTTP parsing, cookies,
CSRF, redirects, request validation, DI, and connection lifecycle. UniAuth owns identity
orchestration, policy checks, verification lifecycle, and local session records.

Use these recipes as transport composition patterns, not as framework bindings inside the package.

Use this document for:

- service bootstrap;
- framework route/controller composition;
- server-module ownership boundaries.

Use [Session transport recipes](session-transport.md) for token extraction, cookie vs bearer
transport, and request auth middleware/preHandler shape. Use
[Account security recipes](account-security.md) for device lists, sign-in method screens, revoke
flows, account closure, password-management handoff, and safe read-side projections.
Use [Support and admin inspection recipe](support-inspection.md) for trusted operator tooling that
stays server-only.

## Shared Bootstrap

Keep service construction in one server-only module:

```ts
import { DefaultAuthService } from '@alyldas/uniauth'
import { createPostgresAuthStore } from '@alyldas/uniauth/postgres'

const store = createPostgresAuthStore({ pool })

export const authService = new DefaultAuthService({
  repos: store,
  transaction: store,
  emailSender,
  smsSender,
  passwordHasher,
  rateLimiter,
  normalizer,
})
```

What stays application-owned even in this shared bootstrap:

- database pool creation and shutdown;
- SMTP/SMS provider setup;
- rate-limit backend and bucket policy;
- password hashing runtime and parameters;
- secret loading, cookie secrets, and CSRF configuration.

For storage and transaction constraints, see [Postgres persistence](postgres.md). For security
invariants, see [Security model](security.md) and [Threat model](threat-model.md). For package gate
and release flow, see [Development](development.md) and the root [release checklist](../README.md#release-checklist).

## Ownership Matrix

| Concern                                         | UniAuth | Application / Framework |
| ----------------------------------------------- | ------- | ----------------------- |
| Sign-in, link, unlink, merge policy             | Yes     | No                      |
| Verification creation and hashed secret storage | Yes     | No                      |
| HTTP routes, JSON parsing, validation errors    | No      | Yes                     |
| Browser cookies and session transport           | No      | Yes                     |
| CSRF middleware or state/nonce cookies          | No      | Yes                     |
| Database pool and migrations                    | No      | Yes                     |
| Provider SDK clients and OAuth callback routing | No      | Yes                     |

## Express

Use Express when you want explicit middleware order and fully manual response handling.

See the runnable [Express auth module example](../examples/express-auth/index.ts) for a larger
module-shaped variant that includes app-owned sender wiring, session cookie issuance, session
resolution middleware, and neutral error mapping.

```ts
import express from 'express'
import { authService } from './auth-service.js'

const app = express()

app.use(express.json())

app.post('/auth/password/sign-in', async (req, res, next) => {
  try {
    const result = await authService.signInWithPassword({
      email: req.body.email,
      password: req.body.password,
    })

    res.cookie('session', sealSessionToken(result.sessionToken), {
      httpOnly: true,
      sameSite: 'lax',
      secure: true,
      path: '/',
    })
    res.status(200).json({ userId: result.user.id })
  } catch (error) {
    next(error)
  }
})
```

For Express session middleware shape, bearer-vs-cookie extraction, and the
`resolveSessionContext({ sessionToken, touch })` helper, use
[Session transport recipes](session-transport.md). The runnable
[Express auth module example](../examples/express-auth/index.ts) already shows that middleware in
context.

Express ownership notes:

- Validate body shape before calling UniAuth.
- Set cookie flags yourself after finish flows; UniAuth only returns the local session record.
- Apply CSRF middleware to browser-originating POST routes such as password sign-in, link, unlink,
  recovery start, and OTP start.
- Keep route-neutral errors neutral at the HTTP layer too; do not translate invalid credentials into
  account existence hints.
- For account-security screens and mutations, use [Account security recipes](account-security.md)
  and prefer `getCurrentAccountInspectionSnapshot({ sessionToken, audit? })` plus the token-based
  self-service profile update, link, revoke, unlink, password-action, account-closure, and
  recent-auth helpers instead of reading adapter internals or re-routing current-account writes
  through raw `userId` calls.

## Fastify

Use Fastify when you want schema-driven request validation and plugin-based server composition.

See the runnable [Fastify auth module example](../examples/fastify-auth/index.ts) for a
module-shaped variant that keeps Fastify schemas, cookie transport, app-owned sender adapters, and
session preHandlers in the framework layer.

```ts
import Fastify from 'fastify'
import cookie from '@fastify/cookie'
import { authService } from './auth-service.js'

const app = Fastify()

await app.register(cookie)

app.post('/auth/magic/finish', async (request, reply) => {
  const result = await authService.finishEmailMagicLinkSignIn({
    verificationId: request.body.verificationId,
    secret: request.body.secret,
  })

  reply.setCookie('session', sealSessionToken(result.sessionToken), {
    httpOnly: true,
    sameSite: 'lax',
    secure: true,
    path: '/',
  })

  return { userId: result.user.id }
})
```

For Fastify session `preHandler` shape, token extraction, and neutral `401` mapping, use
[Session transport recipes](session-transport.md). The runnable
[Fastify auth module example](../examples/fastify-auth/index.ts) keeps that logic in the framework
layer.

Fastify ownership notes:

- Let Fastify schemas reject malformed input before it reaches UniAuth.
- Keep cookie and CSRF plugins in the Fastify layer, not in sender/provider adapters.
- If delivery goes through queues, keep that inside your `EmailSender` or `SmsSender` adapters
  rather than introducing a Fastify-specific auth dispatcher.
- For a fuller copyable token/session recipe, see [Session transport recipes](session-transport.md).
- For sign-in-method, device-management, revoke, account-closure, and password-change routes, use
  [Account security recipes](account-security.md) and the current-account aggregate plus token-based
  action, linking, and recent-auth helpers instead of rebuilding session + user + snapshot
  composition by hand.

## Nest

Use Nest when you want DI, modules, guards, and controller/service separation.

```ts
import { Body, Controller, Post, Res } from '@nestjs/common'
import type { Response } from 'express'
import { AuthServiceFacade } from './auth-service.facade.js'

@Controller('auth/password')
export class PasswordAuthController {
  constructor(private readonly auth: AuthServiceFacade) {}

  @Post('sign-in')
  async signIn(
    @Body() body: { email: string; password: string },
    @Res({ passthrough: true }) res: Response,
  ) {
    const result = await this.auth.signInWithPassword(body)

    res.cookie('session', sealSessionToken(result.sessionToken), {
      httpOnly: true,
      sameSite: 'lax',
      secure: true,
      path: '/',
    })

    return { userId: result.user.id }
  }
}
```

Nest ownership notes:

- Keep `DefaultAuthService` wiring in a provider or facade, not inside controllers.
- Use Nest guards/interceptors for CSRF, cookie policy, logging, and exception mapping.
- If you run Nest with Fastify instead of Express, the UniAuth wiring stays the same; only the HTTP
  transport layer changes.

## Next Backend

Use Next Route Handlers or Server Actions only as a thin HTTP shell around a server-only auth
service module.

```ts
import { cookies } from 'next/headers'
import { NextResponse } from 'next/server'
import { authService } from '@/server/auth-service'

export async function POST(request: Request) {
  const body = await request.json()
  const result = await authService.finishOtpSignIn({
    verificationId: body.verificationId,
    secret: body.secret,
  })

  cookies().set('session', sealSessionToken(result.sessionToken), {
    httpOnly: true,
    sameSite: 'lax',
    secure: true,
    path: '/',
  })

  return NextResponse.json({ userId: result.user.id })
}
```

Next ownership notes:

- Keep UniAuth on the Node.js runtime, not on an Edge route that cannot satisfy your hashing,
  database, or SMTP dependencies.
- Store OAuth state, nonce, and CSRF cookies in the Next layer; the `@alyldas/uniauth/bridges`
  helpers only map already-validated callback data.
- Keep the service bootstrap under a server-only path and never import it into client components.

## Persistence Boundary

The framework should depend on an application-owned store module, not inline repository wiring per
route. That store module can use the reference Postgres adapter or your own implementation.

Recommended shape:

1. `server/auth-store.ts`: creates repositories and `UnitOfWork`
2. `server/auth-service.ts`: creates `DefaultAuthService`
3. framework routes/controllers: call the service and translate HTTP concerns

This keeps pool lifecycle, transactions, and migration ownership out of request handlers.

## Repository Examples

The repository keeps small transport-facing examples alongside these framework notes:

- [Express auth module example](../examples/express-auth/index.ts)
- [Fastify auth module example](../examples/fastify-auth/index.ts)
- [Current-account contact change example](../examples/current-account-contact-change/index.ts)
- [OTP backend wiring example](../examples/otp-backend/index.ts)
- [OAuth / OIDC wiring example](../examples/oauth-oidc/index.ts)
- [Provider token persistence](provider-token-persistence.md)
- [Messenger provider wiring notes](messenger-providers.md)

## Cookie And CSRF Rules

UniAuth does not issue browser cookies or validate CSRF tokens. Treat these as mandatory
application-level concerns whenever a browser can trigger authenticated state changes.

Minimum expectations:

- seal or encrypt raw bearer session tokens before storing them in browser cookies;
- use `httpOnly`, `secure`, and explicit `sameSite` for session cookies;
- scope cookies to the smallest practical path/domain;
- protect browser POST routes with CSRF controls or same-site guarantees that actually match your
  deployment;
- keep OAuth `state` and `nonce` validation in the application callback layer;
- clear browser cookies separately when a local UniAuth session is revoked.

For bearer and mobile client transport choices around local sessions, see
[Session transport recipes](session-transport.md).

## Self-Service Profile Update

Keep local auth profile updates on the same trusted `sessionToken` boundary as other
current-account routes:

```ts
app.patch('/auth/account/profile', requireSession, async (req, res, next) => {
  try {
    const user = await authService.updateCurrentAccountProfileByToken({
      sessionToken: req.auth.sessionToken,
      displayName: req.body.displayName,
      reAuthenticatedAt: req.auth.reAuthenticatedAt,
    })

    res.status(200).json({
      id: user.id,
      displayName: user.displayName ?? null,
      updatedAt: user.updatedAt.toISOString(),
    })
  } catch (error) {
    next(error)
  }
})
```

Validate request body shape in the framework layer before calling the helper. Core trims display
names and treats blank values as clearing the local auth display name. Email, phone, avatars, media
storage, billing profile, and application-specific profile tables remain application-owned or
identity-flow-owned.

## Self-Service Contact Change

Keep verified email and phone changes on the same trusted `sessionToken` boundary. Core owns the
OTP challenge lifecycle and the local `User` contact field update; the application still owns body
validation, UI labels, cookie rotation, notification preferences, and any product profile tables:

```ts
app.post('/auth/account/contact-change/start', requireSession, async (req, res, next) => {
  try {
    const started = await authService.startCurrentAccountContactChange({
      sessionToken: req.auth.sessionToken,
      channel: req.body.channel,
      target: req.body.target,
      reAuthenticatedAt: req.auth.reAuthenticatedAt,
    })

    res.status(202).json({
      verificationId: started.verificationId,
      expiresAt: started.expiresAt.toISOString(),
      delivery: started.delivery,
    })
  } catch (error) {
    next(error)
  }
})
```

```ts
app.post('/auth/account/contact-change/finish', requireSession, async (req, res, next) => {
  try {
    const user = await authService.finishCurrentAccountContactChange({
      sessionToken: req.auth.sessionToken,
      verificationId: req.body.verificationId,
      secret: req.body.code,
    })

    res.status(200).json({
      id: user.id,
      email: user.email ?? null,
      phone: user.phone ?? null,
      updatedAt: user.updatedAt.toISOString(),
    })
  } catch (error) {
    next(error)
  }
})
```

Use `resendCurrentAccountContactChange(...)` and `cancelCurrentAccountContactChange(...)` for
trusted resend and cancellation routes. The helpers update only `User.email` or `User.phone` after
proof of the new target; sign-in identities, password credential subjects, OAuth profiles, avatars,
and downstream application records remain owned by their existing flows.

## Self-Service Account Closure

Keep account closure on the same trusted `sessionToken` boundary as other account-security writes.
If the product offers a pre-closure auth snapshot download, keep that as a read-only route before
the destructive close route:

```ts
app.get('/auth/account/closure-export', requireSession, async (req, res, next) => {
  try {
    const snapshot = await authService.getCurrentAccountClosureExportSnapshot({
      sessionToken: req.auth.sessionToken,
      audit: {
        limit: 50,
      },
    })

    res.status(200).json({
      generatedAt: snapshot.generatedAt.toISOString(),
      account: snapshot.account,
      currentSessionId: snapshot.currentSessionId,
      auditEvents: snapshot.auditEvents,
      nextAuditCursor: snapshot.nextAuditCursor ?? null,
    })
  } catch (error) {
    next(error)
  }
})
```

The closure export helper returns only local auth safe views. The application still owns the file
format, profile data outside local auth, billing records, legal retention, and downstream
application-table export.

The close route should enforce recent-auth using your app-owned marker, call core once, and then
clear browser transport state after the helper succeeds:

```ts
app.post('/auth/account/close', requireSession, async (req, res, next) => {
  try {
    await authService.closeCurrentAccountByToken({
      sessionToken: req.auth.sessionToken,
      reAuthenticatedAt: req.auth.reAuthenticatedAt,
    })

    clearSessionCookie(res)
    res.status(204).send()
  } catch (error) {
    next(error)
  }
})
```

Core disables the current user and revokes active local sessions. Keep data export,
legal-retention decisions, billing cancellation, and application-profile deletion in your own
post-success workflow.

## Release And Maintenance Notes

These recipes are intentionally framework-facing documentation, not package exports. If you add a
new framework recipe later, keep the same boundary:

- core stays framework-agnostic;
- framework examples stay in docs or examples;
- package release hygiene still goes through `npm run check`.
