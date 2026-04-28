# Backend Integration Recipes

UniAuth stays headless across all backend frameworks. The framework owns HTTP parsing, cookies,
CSRF, redirects, request validation, DI, and connection lifecycle. UniAuth owns identity
orchestration, policy checks, verification lifecycle, and local session records.

Use these recipes as transport composition patterns, not as framework bindings inside the package.

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

```ts
import express from 'express'
import cookieParser from 'cookie-parser'
import { authService } from './auth-service.js'

const app = express()

app.use(express.json())
app.use(cookieParser())

app.post('/auth/password/sign-in', async (req, res, next) => {
  try {
    const result = await authService.signInWithPassword({
      email: req.body.email,
      password: req.body.password,
    })

    res.cookie('session', result.session.id, {
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

Express ownership notes:

- Validate body shape before calling UniAuth.
- Set cookie flags yourself after finish flows; UniAuth only returns the local session record.
- Apply CSRF middleware to browser-originating POST routes such as password sign-in, link, unlink,
  recovery start, and OTP start.
- Keep route-neutral errors neutral at the HTTP layer too; do not translate invalid credentials into
  account existence hints.

## Fastify

Use Fastify when you want schema-driven request validation and plugin-based server composition.

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

  reply.setCookie('session', result.session.id, {
    httpOnly: true,
    sameSite: 'lax',
    secure: true,
    path: '/',
  })

  return { userId: result.user.id }
})
```

Fastify ownership notes:

- Let Fastify schemas reject malformed input before it reaches UniAuth.
- Keep cookie and CSRF plugins in the Fastify layer, not in sender/provider adapters.
- If delivery goes through queues, keep that inside your `EmailSender` or `SmsSender` adapters
  rather than introducing a Fastify-specific auth dispatcher.

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

    res.cookie('session', result.session.id, {
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

  cookies().set('session', result.session.id, {
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

- [OTP backend wiring example](../examples/otp-backend/index.ts)
- [OAuth / OIDC wiring example](../examples/oauth-oidc/index.ts)
- [Messenger provider wiring notes](messenger-providers.md)

## Cookie And CSRF Rules

UniAuth does not issue browser cookies or validate CSRF tokens. Treat these as mandatory
application-level concerns whenever a browser can trigger authenticated state changes.

Minimum expectations:

- use `httpOnly`, `secure`, and explicit `sameSite` for session cookies;
- scope cookies to the smallest practical path/domain;
- protect browser POST routes with CSRF controls or same-site guarantees that actually match your
  deployment;
- keep OAuth `state` and `nonce` validation in the application callback layer;
- clear browser cookies separately when a local UniAuth session is revoked.

## Release And Maintenance Notes

These recipes are intentionally framework-facing documentation, not package exports. If you add a
new framework recipe later, keep the same boundary:

- core stays framework-agnostic;
- framework examples stay in docs or examples;
- package release hygiene still goes through `npm run check`.
