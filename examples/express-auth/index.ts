import { fileURLToPath } from 'node:url'
import express, { type Express, type NextFunction, type Request, type Response } from 'express'
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
import {
  InMemoryAuthStore,
  InMemoryPasswordHasher,
  InMemoryRateLimiter,
} from '@alyldas/uniauth/testing'

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

class RequestValidationError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'RequestValidationError'
  }
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
          framework: 'express',
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

export async function createExpressAuthExample(): Promise<ExpressAuthExample> {
  const store = new InMemoryAuthStore()
  const emailSender = new ConsoleEmailSender()
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

  app.use((error: unknown, _request: Request, response: Response, next: NextFunction): void => {
    if (response.headersSent) {
      next(error)
      return
    }

    if (isPublicRequestError(error)) {
      response.status(400).json({ error: 'Request cannot be completed.' })
      return
    }

    if (!isUniAuthError(error)) {
      response.status(500).json({ error: 'Internal server error.' })
      return
    }

    if (error.code === UniAuthErrorCode.RateLimited) {
      response.status(429).json({ error: 'Too many auth attempts.' })
      return
    }

    response.status(400).json({
      error: isNeutralPublicError(error.code) ? 'Request cannot be completed.' : error.message,
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
          routes: ['POST /auth/password/sign-in', 'POST /auth/otp/start', 'POST /auth/otp/finish'],
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
  response.cookie('session', sessionToken, {
    httpOnly: true,
    sameSite: 'lax',
    secure: true,
    path: '/',
  })
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
