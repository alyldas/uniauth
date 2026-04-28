import { fileURLToPath } from 'node:url'
import cookie from '@fastify/cookie'
import Fastify, { type FastifyInstance } from 'fastify'
import {
  DefaultAuthService,
  OtpChannel,
  UniAuthErrorCode,
  VerificationPurpose,
  createDefaultAuthPolicy,
  isUniAuthError,
  type EmailSender,
  type UniAuthErrorCode as UniAuthErrorCodeType,
  type VerificationId,
} from '@alyldas/uniauth'
import { InMemoryAuthStore, InMemoryRateLimiter } from '@alyldas/uniauth/testing'

interface FastifyAuthExample {
  readonly app: FastifyInstance
  readonly authService: DefaultAuthService
  readonly emailSender: ConsoleEmailSender
}

interface DeliveredEmail {
  readonly to: string
  readonly subject: string
  readonly text: string
  readonly metadata?: Record<string, unknown>
}

class ConsoleEmailSender implements EmailSender {
  private readonly messages: DeliveredEmail[] = []

  async sendEmail(input: DeliveredEmail): Promise<void> {
    this.messages.push(input)
    console.log(
      JSON.stringify(
        {
          type: 'demo-email',
          framework: 'fastify',
          to: input.to,
          subject: input.subject,
          text: input.text,
        },
        null,
        2,
      ),
    )
  }

  listMessages(): readonly DeliveredEmail[] {
    return [...this.messages]
  }
}

export async function createFastifyAuthExample(): Promise<FastifyAuthExample> {
  const store = new InMemoryAuthStore()
  const emailSender = new ConsoleEmailSender()
  const authService = new DefaultAuthService({
    repos: store,
    transaction: store,
    emailSender,
    rateLimiter: new InMemoryRateLimiter(),
    policy: createDefaultAuthPolicy({ allowAutoLink: false }),
  })
  const app = Fastify()

  await app.register(cookie)

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

      reply.setCookie('session', result.session.id, {
        httpOnly: true,
        sameSite: 'lax',
        secure: true,
        path: '/',
      })

      return reply.status(200).send({
        userId: result.user.id,
        sessionId: result.session.id,
      })
    },
  )

  app.setErrorHandler((error, _request, reply) => {
    if (isFastifyPublicRequestError(error)) {
      reply.status(400).send({ error: 'Request cannot be completed.' })
      return
    }

    if (!isUniAuthError(error)) {
      reply.status(500).send({ error: 'Internal server error.' })
      return
    }

    if (error.code === UniAuthErrorCode.RateLimited) {
      reply.status(429).send({ error: 'Too many auth attempts.' })
      return
    }

    reply.status(400).send({
      error: isNeutralPublicError(error.code) ? 'Request cannot be completed.' : error.message,
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
        routes: ['POST /auth/otp/start', 'POST /auth/otp/finish'],
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

const neutralPublicErrorCodes = new Set<UniAuthErrorCodeType>([
  UniAuthErrorCode.InvalidInput,
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
