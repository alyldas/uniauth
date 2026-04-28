import { fileURLToPath } from 'node:url'
import {
  DefaultAuthService,
  createOAuthOidcProvider,
  type OAuthOidcAuthorizationCodeExchangeInput,
  type OAuthOidcClient,
  type OAuthOidcFetchProfileInput,
} from '@alyldas/uniauth'
import {
  InMemoryAuthStore,
  InMemoryProviderRegistry,
  InMemoryRateLimiter,
} from '@alyldas/uniauth/testing'

interface CallbackRequest {
  readonly query: {
    readonly code: string
    readonly state: string
  }
  readonly cookies: {
    readonly oidcState: string
    readonly oidcCodeVerifier: string
    readonly oidcRedirectUri: string
  }
}

interface SessionCookie {
  readonly name: 'session'
  readonly value: string
  readonly httpOnly: true
  readonly sameSite: 'lax'
  readonly secure: true
  readonly path: '/'
}

interface ClearedCookie {
  readonly name: string
  readonly value: ''
  readonly maxAge: 0
  readonly path: '/'
}

interface RedirectResponse {
  readonly status: 302
  readonly location: '/app'
  readonly body: {
    readonly userId: string
    readonly identityId: string
    readonly provider: string
  }
  readonly cookies: readonly [SessionCookie, ClearedCookie, ClearedCookie, ClearedCookie]
}

class DemoOidcClient implements OAuthOidcClient {
  private readonly exchangeInputs: OAuthOidcAuthorizationCodeExchangeInput[] = []
  private readonly profileInputs: OAuthOidcFetchProfileInput[] = []

  async exchangeCode(
    input: OAuthOidcAuthorizationCodeExchangeInput,
  ): Promise<{ accessToken: string; tokenType: string; scopes: readonly string[] }> {
    this.exchangeInputs.push(input)

    return {
      accessToken: `demo-access-token-for:${input.code}`,
      tokenType: 'Bearer',
      scopes: ['openid', 'email', 'profile'],
    }
  }

  async fetchProfile(input: OAuthOidcFetchProfileInput): Promise<{
    subject: string
    email: string
    emailVerified: true
    displayName: string
    issuer: string
    preferredUsername: string
  }> {
    this.profileInputs.push(input)

    return {
      subject: 'oidc-user-123',
      email: 'alice@example.com',
      emailVerified: true,
      displayName: 'Alice Example',
      issuer: 'https://issuer.example.test',
      preferredUsername: 'alice',
    }
  }

  listExchangeInputs(): readonly OAuthOidcAuthorizationCodeExchangeInput[] {
    return [...this.exchangeInputs]
  }

  listProfileInputs(): readonly OAuthOidcFetchProfileInput[] {
    return [...this.profileInputs]
  }
}

const store = new InMemoryAuthStore()
const providerRegistry = new InMemoryProviderRegistry()
const oidcClient = new DemoOidcClient()

providerRegistry.register(
  createOAuthOidcProvider({
    providerId: 'demo-oidc',
    client: oidcClient,
  }),
)

const authService = new DefaultAuthService({
  repos: store,
  transaction: store,
  providerRegistry,
  rateLimiter: new InMemoryRateLimiter(),
})

function assertStateMatches(expected: string, received: string): void {
  if (expected !== received) {
    throw new Error('OAuth state mismatch.')
  }
}

function buildSessionCookie(sessionId: string): SessionCookie {
  return {
    name: 'session',
    value: sessionId,
    httpOnly: true,
    sameSite: 'lax',
    secure: true,
    path: '/',
  }
}

function clearCookie(name: string): ClearedCookie {
  return {
    name,
    value: '',
    maxAge: 0,
    path: '/',
  }
}

async function finishOidcCallback(request: CallbackRequest): Promise<RedirectResponse> {
  // State, PKCE, and redirect URI storage stay application-owned.
  assertStateMatches(request.cookies.oidcState, request.query.state)

  const result = await authService.signIn({
    provider: 'demo-oidc',
    finishInput: {
      code: request.query.code,
      state: request.query.state,
      payload: {
        redirectUri: request.cookies.oidcRedirectUri,
        codeVerifier: request.cookies.oidcCodeVerifier,
      },
    },
  })

  return {
    status: 302,
    location: '/app',
    body: {
      userId: result.user.id,
      identityId: result.identity.id,
      provider: result.identity.provider,
    },
    cookies: [
      buildSessionCookie(result.session.id),
      clearCookie('oidcState'),
      clearCookie('oidcCodeVerifier'),
      clearCookie('oidcRedirectUri'),
    ],
  }
}

export async function runOAuthOidcExample(): Promise<void> {
  const response = await finishOidcCallback({
    query: {
      code: 'demo-authorization-code',
      state: 'state-123',
    },
    cookies: {
      oidcState: 'state-123',
      oidcCodeVerifier: 'pkce-verifier-123',
      oidcRedirectUri: 'https://app.example.test/auth/callback',
    },
  })

  console.log({
    status: response.status,
    location: response.location,
    sessionCookie: response.cookies[0],
    clearedCookies: response.cookies.slice(1),
    exchangeInput: oidcClient.listExchangeInputs().at(-1),
    profileInput: oidcClient.listProfileInputs().at(-1),
    userId: response.body.userId,
    identityId: response.body.identityId,
  })
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  await runOAuthOidcExample()
}
