import { fileURLToPath } from 'node:url'
import {
  DefaultAuthService,
  OtpChannel,
  VerificationPurpose,
  getRateLimitedErrorDetails,
  toVerificationStatusView,
  type EmailSender,
  type VerificationId,
} from '@alyldas/uniauth'
import { InMemoryAuthStore, InMemoryRateLimiter } from '@alyldas/uniauth/testing'
import {
  assertSessionCookieSealingConfigured,
  sealSessionCookieValue,
} from '../shared/session-cookie.js'
import {
  serializeVerificationResendWindow,
  serializeVerificationStatusView,
} from '../shared/views.js'

interface JsonRequest<TBody> {
  readonly body: TBody
}

interface SessionCookie {
  readonly name: 'session'
  readonly value: string
  readonly httpOnly: true
  readonly sameSite: 'lax'
  readonly secure: true
  readonly path: '/'
}

interface JsonResponse<TBody> {
  readonly status: number
  readonly body: TBody
  readonly cookies?: readonly SessionCookie[]
}

interface RateLimitedBody {
  readonly error: 'rate_limited'
  readonly retryAfterSeconds: number | null
  readonly resetAt: string | null
}

interface StartOtpBody {
  readonly email: string
}

interface FinishOtpBody {
  readonly verificationId: string
  readonly code: string
}

interface DeliveredEmail {
  readonly to: string
  readonly subject: string
  readonly text: string
  readonly metadata?: Record<string, unknown>
}

class AppOwnedEmailSender implements EmailSender {
  private readonly messages: DeliveredEmail[] = []

  async sendEmail(input: DeliveredEmail): Promise<void> {
    // Production code would enqueue SMTP/vendor work here.
    this.messages.push(input)
  }

  listMessages(): readonly DeliveredEmail[] {
    return [...this.messages]
  }
}

const store = new InMemoryAuthStore()
const emailSender = new AppOwnedEmailSender()

const authService = new DefaultAuthService({
  repos: store,
  transaction: store,
  emailSender,
  rateLimiter: new InMemoryRateLimiter(),
})

function buildSessionCookie(sessionToken: string): SessionCookie {
  return {
    name: 'session',
    value: sealSessionCookieValue(sessionToken),
    httpOnly: true,
    sameSite: 'lax',
    secure: true,
    path: '/',
  }
}

async function postOtpStart(
  request: JsonRequest<StartOtpBody>,
): Promise<
  JsonResponse<{ verificationId: string; delivery: OtpChannel }> | JsonResponse<RateLimitedBody>
> {
  try {
    const challenge = await authService.startOtpChallenge({
      purpose: VerificationPurpose.SignIn,
      channel: OtpChannel.Email,
      target: request.body.email,
    })

    return {
      status: 202,
      body: {
        verificationId: challenge.verificationId,
        delivery: challenge.delivery,
      },
    }
  } catch (error) {
    const details = getRateLimitedErrorDetails(error)

    if (!details) {
      throw error
    }

    return {
      status: 429,
      body: {
        error: 'rate_limited',
        retryAfterSeconds: details.retryAfterSeconds ?? null,
        resetAt: details.resetAt ?? null,
      },
    }
  }
}

async function postOtpFinish(
  request: JsonRequest<FinishOtpBody>,
): Promise<JsonResponse<{ userId: string; sessionRecordId: string }>> {
  const result = await authService.finishOtpSignIn({
    verificationId: parseVerificationId(request.body.verificationId),
    secret: request.body.code,
  })

  return {
    status: 200,
    body: {
      userId: result.user.id,
      sessionRecordId: result.session.id,
    },
    cookies: [buildSessionCookie(result.sessionToken)],
  }
}

async function getVerificationStatus(
  verificationId: VerificationId,
): Promise<JsonResponse<ReturnType<typeof serializeVerificationStatusView>>> {
  const verification = await authService.getVerification(verificationId)

  return {
    status: 200,
    body: serializeVerificationStatusView(toVerificationStatusView(verification)),
  }
}

async function getVerificationWindow(
  verificationId: VerificationId,
): Promise<JsonResponse<ReturnType<typeof serializeVerificationResendWindow>>> {
  const verificationWindow = await authService.getVerificationResendWindow({
    verificationId,
  })

  return {
    status: 200,
    body: serializeVerificationResendWindow(verificationWindow),
  }
}

function extractOtpCode(message: DeliveredEmail): string {
  const match = /\b(\d{4,8})\b/u.exec(message.text)

  if (!match) {
    throw new Error('OTP code was not found in the delivered email.')
  }

  const code = match[1]

  if (!code) {
    throw new Error('OTP code capture group is missing.')
  }

  return code
}

function parseVerificationId(value: string): VerificationId {
  const trimmed = value.trim()

  if (!trimmed) {
    throw new Error('verificationId is required.')
  }

  return trimmed as VerificationId
}

export async function runOtpBackendExample(): Promise<void> {
  assertSessionCookieSealingConfigured()

  const startResponse = await postOtpStart({
    body: {
      email: 'alice@example.com',
    },
  })

  if (startResponse.status !== 202) {
    throw new Error(`Expected OTP start success, received ${startResponse.status}.`)
  }

  const startedChallenge = startResponse.body as {
    readonly verificationId: string
    readonly delivery: OtpChannel
  }

  const deliveredEmail = emailSender.listMessages().at(-1)

  if (!deliveredEmail) {
    throw new Error('Expected the application-owned sender to capture one email message.')
  }

  const pendingVerification = await getVerificationStatus(
    parseVerificationId(startedChallenge.verificationId),
  )
  const pendingWindow = await getVerificationWindow(
    parseVerificationId(startedChallenge.verificationId),
  )
  const finishResponse = await postOtpFinish({
    body: {
      verificationId: startedChallenge.verificationId,
      code: extractOtpCode(deliveredEmail),
    },
  })
  const consumedVerification = await getVerificationStatus(
    parseVerificationId(startedChallenge.verificationId),
  )

  console.log({
    startStatus: startResponse.status,
    pendingVerification: pendingVerification.body,
    pendingWindow: pendingWindow.body,
    deliveredTo: deliveredEmail.to,
    deliveredText: deliveredEmail.text,
    finishStatus: finishResponse.status,
    consumedVerification: consumedVerification.body,
    sessionCookie: finishResponse.cookies?.[0],
    userId: finishResponse.body.userId,
  })
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  await runOtpBackendExample()
}
