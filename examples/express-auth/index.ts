import { fileURLToPath } from 'node:url'
import express, { type Express, type NextFunction, type Request, type Response } from 'express'
import {
  DefaultAuthService,
  OtpChannel,
  SessionStatus,
  UniAuthErrorCode,
  VerificationPurpose,
  createDefaultAuthPolicy,
  isUniAuthError,
  toAccountSecuritySnapshot,
  type Session,
  type User,
  type UniAuthErrorCode as UniAuthErrorCodeType,
  type VerificationId,
} from '@alyldas/uniauth'
import {
  InMemoryAuthStore,
  InMemoryPasswordHasher,
  InMemoryRateLimiter,
} from '@alyldas/uniauth/testing'
import { ConsoleEmailSender } from '../shared/email.js'
import {
  AUTHENTICATION_REQUIRED_MESSAGE,
  REQUEST_CANNOT_BE_COMPLETED_MESSAGE,
  TOO_MANY_AUTH_ATTEMPTS_MESSAGE,
  isSessionContextError,
  readBearerToken,
  readCookieHeaderToken,
} from '../shared/http.js'
import {
  assertSessionCookieSealingConfigured,
  sealSessionCookieValue,
  unsealSessionCookieValue,
} from '../shared/session-cookie.js'
import { serializeAccountSecuritySnapshot } from '../shared/views.js'

interface ExpressAuthExample {
  readonly app: Express
  readonly authService: DefaultAuthService
  readonly emailSender: ConsoleEmailSender
  readonly demoAccount: DemoAccount
}

interface DemoAccount {
  readonly email: string
  readonly password: string
}

interface ExpressRequestAuth {
  readonly session: Session
  readonly user: User
  readonly userId: Session['userId']
}

declare module 'express-serve-static-core' {
  interface Request {
    auth?: ExpressRequestAuth
  }
}

class RequestValidationError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'RequestValidationError'
  }
}

export async function createExpressAuthExample(): Promise<ExpressAuthExample> {
  assertSessionCookieSealingConfigured()

  const store = new InMemoryAuthStore()
  const emailSender = new ConsoleEmailSender('express')
  const authService = new DefaultAuthService({
    repos: store,
    transaction: store,
    emailSender,
    passwordHasher: new InMemoryPasswordHasher(),
    rateLimiter: new InMemoryRateLimiter(),
    policy: createDefaultAuthPolicy({ allowAutoLink: false }),
  })
  const demoAccount = await seedDemoAccount(authService)
  const app = express()

  app.use(express.json())

  const sessionMiddleware = createExpressSessionMiddleware(authService, {
    touch: true,
  })

  app.post('/auth/password/sign-in', async (request, response, next) => {
    try {
      const email = readRequiredString(request.body?.email, 'email')
      const password = readRequiredString(request.body?.password, 'password')
      const result = await authService.signInWithPassword({
        email,
        password,
        metadata: { transport: 'express', route: 'password-sign-in' },
      })

      writeSessionCookie(response, result.sessionToken)
      response.status(200).json({
        userId: result.user.id,
        sessionRecordId: result.session.id,
      })
    } catch (error) {
      next(error)
    }
  })

  app.post('/auth/otp/start', async (request, response, next) => {
    try {
      const email = readRequiredString(request.body?.email, 'email')
      const challenge = await authService.startOtpChallenge({
        purpose: VerificationPurpose.SignIn,
        channel: OtpChannel.Email,
        target: email,
        metadata: { transport: 'express', route: 'otp-start' },
      })

      response.status(202).json({
        verificationId: challenge.verificationId,
        delivery: challenge.delivery,
      })
    } catch (error) {
      next(error)
    }
  })

  app.post('/auth/otp/finish', async (request, response, next) => {
    try {
      const verificationId = parseVerificationId(
        readRequiredString(request.body?.verificationId, 'verificationId'),
      )
      const code = readRequiredString(request.body?.code, 'code')
      const result = await authService.finishOtpSignIn({
        verificationId,
        secret: code,
        metadata: { transport: 'express', route: 'otp-finish' },
      })

      writeSessionCookie(response, result.sessionToken)
      response.status(200).json({
        userId: result.user.id,
        sessionRecordId: result.session.id,
      })
    } catch (error) {
      next(error)
    }
  })

  app.get('/me', sessionMiddleware, requireExpressSession, (request, response) => {
    const auth = request.auth

    if (!auth) {
      response.status(401).json({ error: AUTHENTICATION_REQUIRED_MESSAGE })
      return
    }

    response.status(200).json({
      user: {
        id: auth.user.id,
        email: auth.user.email ?? null,
        displayName: auth.user.displayName ?? null,
      },
      sessionRecordId: auth.session.id,
      sessionStatus: auth.session.status,
      lastSeenAt: auth.session.lastSeenAt?.toISOString() ?? null,
    })
  })

  app.get(
    '/account/security',
    sessionMiddleware,
    requireExpressSession,
    async (request, response, next) => {
      try {
        const auth = request.auth

        if (!auth) {
          response.status(401).json({ error: AUTHENTICATION_REQUIRED_MESSAGE })
          return
        }

        const [identities, credentials, sessions] = await Promise.all([
          authService.getUserIdentities(auth.user.id),
          authService.getUserCredentials(auth.user.id),
          authService.getUserSessions(auth.user.id),
        ])
        const snapshot = toAccountSecuritySnapshot({
          user: auth.user,
          identities,
          credentials,
          sessions,
        })

        response.status(200).json(serializeAccountSecuritySnapshot(snapshot))
      } catch (error) {
        next(error)
      }
    },
  )

  app.use((error: unknown, _request: Request, response: Response, next: NextFunction): void => {
    if (response.headersSent) {
      next(error)
      return
    }

    if (isPublicRequestError(error)) {
      response.status(400).json({ error: REQUEST_CANNOT_BE_COMPLETED_MESSAGE })
      return
    }

    if (!isUniAuthError(error)) {
      response.status(500).json({ error: 'Internal server error.' })
      return
    }

    if (error.code === UniAuthErrorCode.RateLimited) {
      response.status(429).json({ error: TOO_MANY_AUTH_ATTEMPTS_MESSAGE })
      return
    }

    response.status(400).json({
      error: isNeutralPublicError(error.code) ? REQUEST_CANNOT_BE_COMPLETED_MESSAGE : error.message,
    })
  })

  return {
    app,
    authService,
    emailSender,
    demoAccount,
  }
}

export async function runExpressAuthExample(): Promise<void> {
  const port = Number(process.env.PORT ?? '3000')
  const example = await createExpressAuthExample()

  example.app.listen(port, () => {
    console.log(
      JSON.stringify(
        {
          type: 'demo-server',
          framework: 'express',
          port,
          demoAccount: example.demoAccount,
          routes: [
            'POST /auth/password/sign-in',
            'POST /auth/otp/start',
            'POST /auth/otp/finish',
            'GET /me',
            'GET /account/security',
          ],
          note: 'OTP codes are printed by the application-owned email sender.',
        },
        null,
        2,
      ),
    )
  })
}

async function seedDemoAccount(authService: DefaultAuthService): Promise<DemoAccount> {
  const demoAccount = {
    email: 'demo@example.com',
    password: 'demo-password-123',
  }
  const initial = await authService.signIn({
    assertion: {
      provider: 'express-demo-seed',
      providerUserId: demoAccount.email,
      email: demoAccount.email,
      emailVerified: true,
      displayName: 'Express Demo User',
    },
    metadata: { seed: true },
  })

  await authService.setPassword({
    userId: initial.user.id,
    email: demoAccount.email,
    password: demoAccount.password,
    metadata: { seed: true },
  })

  return demoAccount
}

function readRequiredString(value: unknown, name: string): string {
  if (typeof value !== 'string' || !value.trim()) {
    throw new RequestValidationError(`${name} is required.`)
  }

  return value.trim()
}

function parseVerificationId(value: string): VerificationId {
  return value as VerificationId
}

function writeSessionCookie(response: Response, sessionToken: string): void {
  response.cookie('session', sealSessionCookieValue(sessionToken), {
    httpOnly: true,
    sameSite: 'lax',
    secure: true,
    path: '/',
  })
}

function createExpressSessionMiddleware(
  authService: DefaultAuthService,
  options: {
    readonly touch?: boolean
  } = {},
) {
  return async (request: Request, response: Response, next: NextFunction): Promise<void> => {
    const sessionToken = readExpressSessionToken(request)

    if (!sessionToken) {
      next()
      return
    }

    try {
      const resolved = await authService.resolveSession({ sessionToken })
      const session = options.touch
        ? await authService.touchSession({ sessionId: resolved.id })
        : resolved
      const user = await authService.getUser(session.userId)

      request.auth = {
        session,
        user,
        userId: session.userId,
      }
      next()
    } catch (error) {
      if (isSessionContextError(error)) {
        response.status(401).json({ error: AUTHENTICATION_REQUIRED_MESSAGE })
        return
      }

      next(error)
    }
  }
}

function requireExpressSession(request: Request, response: Response, next: NextFunction): void {
  if (!request.auth || request.auth.session.status !== SessionStatus.Active) {
    response.status(401).json({ error: AUTHENTICATION_REQUIRED_MESSAGE })
    return
  }

  next()
}

function readExpressSessionToken(request: Request): string | undefined {
  return (
    readBearerToken(request.headers.authorization) ??
    unsealSessionCookieValue(readCookieHeaderToken(request.headers.cookie, 'session'))
  )
}

const neutralPublicErrorCodes = new Set<UniAuthErrorCodeType>([
  UniAuthErrorCode.InvalidCredentials,
  UniAuthErrorCode.InvalidInput,
  UniAuthErrorCode.VerificationNotFound,
  UniAuthErrorCode.VerificationExpired,
  UniAuthErrorCode.VerificationConsumed,
  UniAuthErrorCode.VerificationInvalidSecret,
])

function isNeutralPublicError(code: UniAuthErrorCodeType): boolean {
  return neutralPublicErrorCodes.has(code)
}

function isPublicRequestError(error: unknown): boolean {
  if (error instanceof RequestValidationError) {
    return true
  }

  if (!(error instanceof SyntaxError)) {
    return false
  }

  const candidate = error as SyntaxError & { status?: unknown; body?: unknown }

  return candidate.status === 400 && 'body' in candidate
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  await runExpressAuthExample()
}
