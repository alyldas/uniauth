import { fileURLToPath } from 'node:url'
import cookie from '@fastify/cookie'
import Fastify, { type FastifyInstance, type FastifyReply, type FastifyRequest } from 'fastify'
import {
  DefaultAuthService,
  OtpChannel,
  SessionStatus,
  UniAuthErrorCode,
  VerificationPurpose,
  createDefaultAuthPolicy,
  isUniAuthError,
  type Session,
  type UniAuthErrorCode as UniAuthErrorCodeType,
  type VerificationId,
} from '@alyldas/uniauth'
import { InMemoryAuthStore, InMemoryRateLimiter } from '@alyldas/uniauth/testing'
import { ConsoleEmailSender } from '../shared/email.js'
import {
  AUTHENTICATION_REQUIRED_MESSAGE,
  REQUEST_CANNOT_BE_COMPLETED_MESSAGE,
  TOO_MANY_AUTH_ATTEMPTS_MESSAGE,
  isSessionContextError,
  readBearerToken,
  readCookieValue,
} from '../shared/http.js'

interface FastifyAuthExample {
  readonly app: FastifyInstance
  readonly authService: DefaultAuthService
  readonly emailSender: ConsoleEmailSender
}

interface FastifyRequestAuth {
  readonly session: Session
  readonly userId: Session['userId']
}

declare module 'fastify' {
  interface FastifyRequest {
    auth?: FastifyRequestAuth
  }
}

export async function createFastifyAuthExample(): Promise<FastifyAuthExample> {
  const store = new InMemoryAuthStore()
  const emailSender = new ConsoleEmailSender('fastify')
  const authService = new DefaultAuthService({
    repos: store,
    transaction: store,
    emailSender,
    rateLimiter: new InMemoryRateLimiter(),
    policy: createDefaultAuthPolicy({ allowAutoLink: false }),
  })
  const app = Fastify()

  await app.register(cookie)
  app.decorateRequest('auth')
  const sessionPreHandler = createFastifySessionPreHandler(authService, {
    touch: true,
  })

  app.post<{
    Body: {
      email: string
    }
  }>(
    '/auth/otp/start',
    {
      schema: {
        body: {
          type: 'object',
          required: ['email'],
          properties: {
            email: { type: 'string', minLength: 1 },
          },
        },
      },
    },
    async (request, reply) => {
      const challenge = await authService.startOtpChallenge({
        purpose: VerificationPurpose.SignIn,
        channel: OtpChannel.Email,
        target: request.body.email,
        metadata: { transport: 'fastify', route: 'otp-start' },
      })

      return reply.status(202).send({
        verificationId: challenge.verificationId,
        delivery: challenge.delivery,
      })
    },
  )

  app.post<{
    Body: {
      verificationId: string
      code: string
    }
  }>(
    '/auth/otp/finish',
    {
      schema: {
        body: {
          type: 'object',
          required: ['verificationId', 'code'],
          properties: {
            verificationId: { type: 'string', minLength: 1 },
            code: { type: 'string', minLength: 1 },
          },
        },
      },
    },
    async (request, reply) => {
      const result = await authService.finishOtpSignIn({
        verificationId: parseVerificationId(request.body.verificationId),
        secret: request.body.code,
        metadata: { transport: 'fastify', route: 'otp-finish' },
      })

      reply.setCookie('session', result.sessionToken, {
        httpOnly: true,
        sameSite: 'lax',
        secure: true,
        path: '/',
      })

      return reply.status(200).send({
        userId: result.user.id,
        sessionRecordId: result.session.id,
      })
    },
  )

  app.get(
    '/me',
    {
      preHandler: [sessionPreHandler, requireFastifySession],
    },
    async (request, reply) => {
      const auth = request.auth

      if (!auth) {
        return reply.status(401).send({ error: AUTHENTICATION_REQUIRED_MESSAGE })
      }

      return reply.status(200).send({
        userId: auth.userId,
        sessionRecordId: auth.session.id,
        sessionStatus: auth.session.status,
        lastSeenAt: auth.session.lastSeenAt?.toISOString() ?? null,
      })
    },
  )

  app.setErrorHandler((error, _request, reply) => {
    if (isFastifyPublicRequestError(error)) {
      reply.status(400).send({ error: REQUEST_CANNOT_BE_COMPLETED_MESSAGE })
      return
    }

    if (!isUniAuthError(error)) {
      reply.status(500).send({ error: 'Internal server error.' })
      return
    }

    if (error.code === UniAuthErrorCode.RateLimited) {
      reply.status(429).send({ error: TOO_MANY_AUTH_ATTEMPTS_MESSAGE })
      return
    }

    reply.status(400).send({
      error: isNeutralPublicError(error.code) ? REQUEST_CANNOT_BE_COMPLETED_MESSAGE : error.message,
    })
  })

  return {
    app,
    authService,
    emailSender,
  }
}

export async function runFastifyAuthExample(): Promise<void> {
  const port = Number(process.env.PORT ?? '3001')
  const example = await createFastifyAuthExample()

  await example.app.listen({ port, host: '127.0.0.1' })

  console.log(
    JSON.stringify(
      {
        type: 'demo-server',
        framework: 'fastify',
        port,
        routes: ['POST /auth/otp/start', 'POST /auth/otp/finish', 'GET /me'],
        note: 'OTP codes are printed by the application-owned email sender.',
      },
      null,
      2,
    ),
  )
}

function parseVerificationId(value: string): VerificationId {
  return value.trim() as VerificationId
}

function createFastifySessionPreHandler(
  authService: DefaultAuthService,
  options: {
    readonly touch?: boolean
  } = {},
) {
  return async (request: FastifyRequest, reply: FastifyReply): Promise<void> => {
    const sessionToken = readFastifySessionToken(request)

    if (!sessionToken) {
      return
    }

    try {
      const resolved = await authService.resolveSession({ sessionToken })
      const session = options.touch
        ? await authService.touchSession({ sessionId: resolved.id })
        : resolved

      request.auth = {
        session,
        userId: session.userId,
      }
    } catch (error) {
      if (isSessionContextError(error)) {
        await reply.status(401).send({ error: AUTHENTICATION_REQUIRED_MESSAGE })
        return
      }

      throw error
    }
  }
}

async function requireFastifySession(request: FastifyRequest, reply: FastifyReply): Promise<void> {
  if (!request.auth || request.auth.session.status !== SessionStatus.Active) {
    await reply.status(401).send({ error: AUTHENTICATION_REQUIRED_MESSAGE })
  }
}

function readFastifySessionToken(request: FastifyRequest): string | undefined {
  return readBearerToken(request.headers.authorization) ?? readCookieValue(request.cookies.session)
}

const neutralPublicErrorCodes = new Set<UniAuthErrorCodeType>([
  UniAuthErrorCode.InvalidInput,
  UniAuthErrorCode.SessionNotFound,
  UniAuthErrorCode.VerificationNotFound,
  UniAuthErrorCode.VerificationExpired,
  UniAuthErrorCode.VerificationConsumed,
  UniAuthErrorCode.VerificationInvalidSecret,
])

function isNeutralPublicError(code: UniAuthErrorCodeType): boolean {
  return neutralPublicErrorCodes.has(code)
}

function isFastifyPublicRequestError(error: unknown): boolean {
  if (!error || typeof error !== 'object') {
    return false
  }

  const candidate = error as { statusCode?: unknown; validation?: unknown }

  return candidate.statusCode === 400 || candidate.validation !== undefined
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  await runFastifyAuthExample()
}
