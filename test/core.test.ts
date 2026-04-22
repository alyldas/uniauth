import { createRequire } from 'node:module'
import { describe, expect, it } from 'vitest'
import {
  DefaultAuthService,
  EMAIL_OTP_PROVIDER_ID,
  OtpChannel,
  PHONE_OTP_PROVIDER_ID,
  createDefaultAuthPolicy,
  getUniAuthAttributionNotice,
  isUniAuthError,
  SessionStatus,
  UNIAUTH_ATTRIBUTION,
  UniAuthErrorCode,
  VerificationPurpose,
  VerificationStatus,
  addSeconds,
  asVerificationId,
  type ProviderIdentityAssertion,
} from '../src'
import { InMemoryAuthStore, createInMemoryAuthKit, StaticAuthProvider } from '../src/testing'

interface PackageMetadata {
  readonly name: string
  readonly license: string
  readonly author: {
    readonly name: string
    readonly email: string
  }
}

function formatPackageLicenseName(license: string): string {
  return license
    .replace(/^PolyForm-/, 'PolyForm ')
    .replace(/-(\d+\.\d+\.\d+)$/, ' License $1')
    .replaceAll('-', ' ')
}

const packageMetadata = createRequire(import.meta.url)('../package.json') as PackageMetadata
const packageLicense = formatPackageLicenseName(packageMetadata.license)
const now = new Date('2026-01-01T00:00:00.000Z')

function assertion(input: Partial<ProviderIdentityAssertion> = {}): ProviderIdentityAssertion {
  return {
    provider: input.provider ?? 'email',
    providerUserId: input.providerUserId ?? 'alice',
    email: input.email ?? 'Alice@Example.com',
    emailVerified: input.emailVerified ?? true,
    displayName: input.displayName ?? 'Alice',
    ...(input.phone ? { phone: input.phone } : {}),
    ...(input.phoneVerified !== undefined ? { phoneVerified: input.phoneVerified } : {}),
  }
}

describe('DefaultAuthService', () => {
  it('exports stable attribution metadata and an About/Legal notice helper', () => {
    expect(UNIAUTH_ATTRIBUTION.packageName).toBe(packageMetadata.name)
    expect(UNIAUTH_ATTRIBUTION.contactEmail).toBe(packageMetadata.author.email)
    expect(UNIAUTH_ATTRIBUTION.license).toBe(packageLicense)
    expect(getUniAuthAttributionNotice()).toBe(
      `This product uses ${packageMetadata.name}. ${UNIAUTH_ATTRIBUTION.copyright} License: ${packageLicense}. Licensing contact: ${packageMetadata.author.email}.`,
    )
    expect(
      getUniAuthAttributionNotice({
        includeContact: false,
        includeLicense: false,
        productName: 'Example App',
      }),
    ).toBe(`Example App uses ${packageMetadata.name}. ${UNIAUTH_ATTRIBUTION.copyright}`)
  })

  it('creates a local user, identity, and session for a new sign-in', async () => {
    const { service, store } = createInMemoryAuthKit()

    const result = await service.signIn({ assertion: assertion(), now })

    expect(result.isNewUser).toBe(true)
    expect(result.isNewIdentity).toBe(true)
    expect(result.user.email).toBe('alice@example.com')
    expect(result.identity.email).toBe('alice@example.com')
    expect(result.session.status).toBe(SessionStatus.Active)
    expect(store.listUsers()).toHaveLength(1)
    expect(store.listIdentities()).toHaveLength(1)
    expect(store.listSessions()).toHaveLength(1)
    expect(store.listAuditEvents().map((event) => event.type)).toContain('auth.session_created')
  })

  it('uses exact provider identity match before any profile matching', async () => {
    const { service, store } = createInMemoryAuthKit()

    const first = await service.signIn({ assertion: assertion(), now })
    const second = await service.signIn({
      assertion: assertion({ email: 'different@example.com' }),
      now,
    })

    expect(second.isNewUser).toBe(false)
    expect(second.isNewIdentity).toBe(false)
    expect(second.user.id).toBe(first.user.id)
    expect(store.listUsers()).toHaveLength(1)
    expect(store.listIdentities()).toHaveLength(1)
    expect(store.listSessions()).toHaveLength(2)
  })

  it('does not silently merge users by verified email under the default policy', async () => {
    const { service, store } = createInMemoryAuthKit()

    const emailUser = await service.signIn({ assertion: assertion(), now })
    const oauthUser = await service.signIn({
      assertion: assertion({ provider: 'oauth', providerUserId: 'oauth-alice' }),
      now,
    })

    expect(oauthUser.isNewUser).toBe(true)
    expect(oauthUser.user.id).not.toBe(emailUser.user.id)
    expect(store.listUsers()).toHaveLength(2)
    expect(store.listIdentities()).toHaveLength(2)
  })

  it('auto-links only when the policy explicitly allows it', async () => {
    const { service, store } = createInMemoryAuthKit({
      policy: createDefaultAuthPolicy({ allowAutoLink: true }),
    })

    const emailUser = await service.signIn({ assertion: assertion(), now })
    const oauthUser = await service.signIn({
      assertion: assertion({ provider: 'oauth', providerUserId: 'oauth-alice' }),
      now,
    })

    expect(oauthUser.isNewUser).toBe(false)
    expect(oauthUser.isNewIdentity).toBe(true)
    expect(oauthUser.user.id).toBe(emailUser.user.id)
    expect(store.listUsers()).toHaveLength(1)
    expect(store.listIdentities()).toHaveLength(2)
  })

  it('rejects unlinking the last active identity', async () => {
    const { service } = createInMemoryAuthKit()
    const result = await service.signIn({ assertion: assertion(), now })

    const error = await service
      .unlink({ userId: result.user.id, identityId: result.identity.id, now })
      .catch((caught: unknown) => caught)

    expect(error).toMatchObject({ code: UniAuthErrorCode.LastIdentity })
  })

  it('rejects linking an identity already attached to another user without leaking ownership', async () => {
    const { service } = createInMemoryAuthKit()
    const first = await service.signIn({ assertion: assertion(), now })
    const second = await service.signIn({
      assertion: assertion({
        provider: 'email',
        providerUserId: 'bob',
        email: 'bob@example.com',
        displayName: 'Bob',
      }),
      now,
    })

    const error = await service
      .link({
        userId: second.user.id,
        assertion: assertion({
          provider: first.identity.provider,
          providerUserId: first.identity.providerUserId,
        }),
        now,
      })
      .catch((caught: unknown) => caught)

    expect(isUniAuthError(error)).toBe(true)

    if (!isUniAuthError(error)) {
      throw new Error('Expected a UniAuthError.')
    }

    expect(error.code).toBe(UniAuthErrorCode.IdentityAlreadyLinked)
    expect(error.message).not.toContain('another user')
    expect(error.message).not.toContain('account')
  })

  it('stores verification secrets only as hashes and consumes valid secrets once', async () => {
    const { service, store } = createInMemoryAuthKit()

    const created = await service.createVerification({
      purpose: VerificationPurpose.SignIn,
      target: 'Alice@Example.com',
      secret: '123456',
      now,
    })

    expect(created.secret).toBe('123456')
    expect(created.verification.target).toBe('alice@example.com')
    expect(created.verification.secretHash).not.toBe('123456')
    expect(created.verification.secretHash).toMatch(/^sha256:/)
    expect(store.listVerifications()[0]?.secretHash).toBe(created.verification.secretHash)

    const invalidSecretError = await service
      .consumeVerification({
        verificationId: created.verification.id,
        secret: 'wrong',
        now,
      })
      .catch((caught: unknown) => caught)

    expect(invalidSecretError).toMatchObject({
      code: UniAuthErrorCode.VerificationInvalidSecret,
    })

    const consumed = await service.consumeVerification({
      verificationId: created.verification.id,
      secret: '123456',
      now,
    })

    expect(consumed.status).toBe(VerificationStatus.Consumed)
    const consumedAgainError = await service
      .consumeVerification({
        verificationId: created.verification.id,
        secret: '123456',
        now,
      })
      .catch((caught: unknown) => caught)

    expect(consumedAgainError).toMatchObject({
      code: UniAuthErrorCode.VerificationConsumed,
    })
  })

  it('starts and finishes email OTP sign-in without exposing account state', async () => {
    const { emailSender, service, store } = createInMemoryAuthKit()

    const started = await service.startEmailOtpSignIn({
      email: ' Alice@Example.com ',
      secret: '123456',
      metadata: { requestId: 'req-1' },
      now,
    })

    expect(started).toEqual({
      verificationId: started.verificationId,
      expiresAt: new Date('2026-01-01T00:10:00.000Z'),
      delivery: 'email',
    })
    expect(started).not.toHaveProperty('isNewUser')
    expect(started).not.toHaveProperty('user')

    const [message] = emailSender.listMessages()
    const [storedVerification] = store.listVerifications()

    expect(message).toMatchObject({
      to: 'alice@example.com',
      subject: 'Your sign-in code',
      text: 'Your sign-in code is 123456.',
    })
    expect(message?.metadata).toMatchObject({
      verificationId: started.verificationId,
      purpose: VerificationPurpose.SignIn,
      delivery: 'email',
    })
    expect(storedVerification).toMatchObject({
      id: started.verificationId,
      purpose: VerificationPurpose.SignIn,
      target: 'alice@example.com',
      status: VerificationStatus.Pending,
      metadata: {
        requestId: 'req-1',
        channel: OtpChannel.Email,
        provider: EMAIL_OTP_PROVIDER_ID,
      },
    })
    expect(storedVerification?.secretHash).not.toBe('123456')
    expect(storedVerification?.secretHash).toMatch(/^sha256:/)

    const wrongSecret = await service
      .finishEmailOtpSignIn({
        verificationId: started.verificationId,
        secret: '000000',
        now,
      })
      .catch((caught: unknown) => caught)

    expect(wrongSecret).toMatchObject({
      code: UniAuthErrorCode.VerificationInvalidSecret,
    })
    expect(store.listVerifications()[0]?.status).toBe(VerificationStatus.Pending)

    const finished = await service.finishEmailOtpSignIn({
      verificationId: started.verificationId,
      secret: '123456',
      metadata: { flow: 'otp' },
      now,
    })

    expect(finished.isNewUser).toBe(true)
    expect(finished.identity.provider).toBe(EMAIL_OTP_PROVIDER_ID)
    expect(finished.identity.providerUserId).toBe('alice@example.com')
    expect(finished.identity.email).toBe('alice@example.com')
    expect(finished.session.status).toBe(SessionStatus.Active)
    expect(store.listVerifications()[0]?.status).toBe(VerificationStatus.Consumed)

    const consumedAgain = await service
      .finishEmailOtpSignIn({
        verificationId: started.verificationId,
        secret: '123456',
        now,
      })
      .catch((caught: unknown) => caught)

    expect(consumedAgain).toMatchObject({
      code: UniAuthErrorCode.VerificationConsumed,
    })

    const generated = await service.startEmailOtpSignIn({
      email: 'bob@example.com',
      ttlSeconds: 30,
    })
    const generatedMessage = emailSender.listMessages()[1]
    const generatedSecret = generatedMessage?.text.match(/\d{6}/)?.[0]

    if (!generatedSecret) {
      throw new Error('Expected generated OTP secret in the email message.')
    }

    const generatedFinished = await service.finishEmailOtpSignIn({
      verificationId: generated.verificationId,
      secret: generatedSecret,
      sessionExpiresAt: addSeconds(now, 60),
    })

    expect(generated.delivery).toBe('email')
    expect(generatedFinished.session.expiresAt).toEqual(addSeconds(now, 60))
  })

  it('reuses generic OTP challenges for email and phone sign-in channels', async () => {
    const { emailSender, service, smsSender, store } = createInMemoryAuthKit()

    const emailLinkChallenge = await service.startOtpChallenge({
      purpose: VerificationPurpose.Link,
      channel: OtpChannel.Email,
      target: ' Link@Example.com ',
      secret: '111111',
      now,
    })
    const consumedEmailLink = await service.finishOtpChallenge({
      verificationId: emailLinkChallenge.verificationId,
      secret: '111111',
      purpose: VerificationPurpose.Link,
      channel: OtpChannel.Email,
      now,
    })

    expect(emailLinkChallenge.delivery).toBe(OtpChannel.Email)
    expect(consumedEmailLink.status).toBe(VerificationStatus.Consumed)
    expect(emailSender.listMessages()[0]).toMatchObject({
      to: 'link@example.com',
      text: 'Your sign-in code is 111111.',
    })

    const clockFallbackChallenge = await service.startOtpChallenge({
      purpose: VerificationPurpose.Link,
      channel: OtpChannel.Email,
      target: 'clock@example.com',
      secret: '222222',
    })
    const clockFallbackConsumed = await service.finishOtpChallenge({
      verificationId: clockFallbackChallenge.verificationId,
      secret: '222222',
      purpose: VerificationPurpose.Link,
      channel: OtpChannel.Email,
    })

    expect(clockFallbackConsumed.status).toBe(VerificationStatus.Consumed)

    const phoneChallenge = await service.startOtpChallenge({
      purpose: VerificationPurpose.SignIn,
      channel: OtpChannel.Phone,
      target: ' +1 (555) 123-4567 ',
      secret: '654321',
      metadata: { requestId: 'req-phone' },
      now,
    })

    expect(phoneChallenge).toEqual({
      verificationId: phoneChallenge.verificationId,
      expiresAt: new Date('2026-01-01T00:10:00.000Z'),
      delivery: OtpChannel.Phone,
    })
    expect(smsSender.listMessages()[0]).toMatchObject({
      to: '+15551234567',
      text: 'Your sign-in code is 654321.',
      metadata: {
        verificationId: phoneChallenge.verificationId,
        purpose: VerificationPurpose.SignIn,
        delivery: OtpChannel.Phone,
      },
    })
    expect(store.listVerifications()[2]).toMatchObject({
      id: phoneChallenge.verificationId,
      target: '+15551234567',
      metadata: {
        requestId: 'req-phone',
        channel: OtpChannel.Phone,
        provider: PHONE_OTP_PROVIDER_ID,
      },
    })

    const phoneResult = await service.finishOtpSignIn({
      verificationId: phoneChallenge.verificationId,
      secret: '654321',
      metadata: { flow: 'phone-otp' },
      now,
    })

    expect(phoneResult.identity.provider).toBe(PHONE_OTP_PROVIDER_ID)
    expect(phoneResult.identity.providerUserId).toBe('+15551234567')
    expect(phoneResult.identity.phone).toBe('+15551234567')
    expect(phoneResult.identity.phoneVerified).toBe(true)
    expect(phoneResult.session.status).toBe(SessionStatus.Active)
  })

  it('rejects invalid email OTP sign-in starts and wrong verification purposes', async () => {
    const serviceWithoutEmailSender = new DefaultAuthService({
      repos: new InMemoryAuthStore(),
    })

    expect(
      await serviceWithoutEmailSender
        .startEmailOtpSignIn({ email: 'alice@example.com', now })
        .catch((caught: unknown) => caught),
    ).toMatchObject({ code: UniAuthErrorCode.InvalidInput })
    expect(
      await serviceWithoutEmailSender
        .startEmailOtpSignIn({ email: '   ', now })
        .catch((caught: unknown) => caught),
    ).toMatchObject({ code: UniAuthErrorCode.InvalidInput })
    expect(
      await serviceWithoutEmailSender
        .finishEmailOtpSignIn({
          verificationId: asVerificationId('missing'),
          secret: '123456',
          now,
        })
        .catch((caught: unknown) => caught),
    ).toMatchObject({ code: UniAuthErrorCode.VerificationNotFound })

    const { service, store } = createInMemoryAuthKit()
    const linkVerification = await service.createVerification({
      purpose: VerificationPurpose.Link,
      target: 'alice@example.com',
      secret: '123456',
      now,
    })
    const wrongPurpose = await service
      .finishEmailOtpSignIn({
        verificationId: linkVerification.verification.id,
        secret: '123456',
        now,
      })
      .catch((caught: unknown) => caught)

    expect(wrongPurpose).toMatchObject({ code: UniAuthErrorCode.InvalidInput })
    expect(store.listVerifications()[0]?.status).toBe(VerificationStatus.Pending)
  })

  it('rejects invalid generic OTP challenge usage without consuming secrets', async () => {
    const serviceWithoutSmsSender = new DefaultAuthService({
      repos: new InMemoryAuthStore(),
    })

    expect(
      await serviceWithoutSmsSender
        .startOtpChallenge({
          purpose: VerificationPurpose.SignIn,
          channel: OtpChannel.Phone,
          target: '+15551234567',
          now,
        })
        .catch((caught: unknown) => caught),
    ).toMatchObject({ code: UniAuthErrorCode.InvalidInput })
    expect(
      await serviceWithoutSmsSender
        .startOtpChallenge({
          purpose: VerificationPurpose.SignIn,
          channel: 'push',
          target: 'alice',
          now,
        })
        .catch((caught: unknown) => caught),
    ).toMatchObject({ code: UniAuthErrorCode.InvalidInput })
    expect(
      await serviceWithoutSmsSender
        .startOtpChallenge({
          purpose: VerificationPurpose.SignIn,
          channel: 'push',
          target: '   ',
          now,
        })
        .catch((caught: unknown) => caught),
    ).toMatchObject({ code: UniAuthErrorCode.InvalidInput })
    expect(
      await serviceWithoutSmsSender
        .startOtpChallenge({
          purpose: VerificationPurpose.SignIn,
          channel: OtpChannel.Phone,
          target: '   ',
          now,
        })
        .catch((caught: unknown) => caught),
    ).toMatchObject({ code: UniAuthErrorCode.InvalidInput })

    const { service, store } = createInMemoryAuthKit()
    const challenge = await service.startOtpChallenge({
      purpose: VerificationPurpose.SignIn,
      channel: OtpChannel.Email,
      target: 'alice@example.com',
      secret: '123456',
      now,
    })
    const wrongChannel = await service
      .finishOtpChallenge({
        verificationId: challenge.verificationId,
        secret: '123456',
        purpose: VerificationPurpose.SignIn,
        channel: OtpChannel.Phone,
        now,
      })
      .catch((caught: unknown) => caught)

    expect(wrongChannel).toMatchObject({ code: UniAuthErrorCode.InvalidInput })
    expect(store.listVerifications()[0]?.status).toBe(VerificationStatus.Pending)

    const rawVerification = await service.createVerification({
      purpose: VerificationPurpose.SignIn,
      target: 'raw@example.com',
      secret: '123456',
      now,
    })
    const notOtpChallenge = await service
      .finishOtpChallenge({
        verificationId: rawVerification.verification.id,
        secret: '123456',
        now,
      })
      .catch((caught: unknown) => caught)

    expect(notOtpChallenge).toMatchObject({ code: UniAuthErrorCode.InvalidInput })
    expect(store.listVerifications()[1]?.status).toBe(VerificationStatus.Pending)
  })

  it('requires explicit merge policy and moves identities only through mergeAccounts', async () => {
    const deniedKit = createInMemoryAuthKit()
    const deniedSource = await deniedKit.service.signIn({
      assertion: assertion({ providerUserId: 'source', email: 'source@example.com' }),
      now,
    })
    const deniedTarget = await deniedKit.service.signIn({
      assertion: assertion({ providerUserId: 'target', email: 'target@example.com' }),
      now,
    })

    const deniedMergeError = await deniedKit.service
      .mergeAccounts({
        sourceUserId: deniedSource.user.id,
        targetUserId: deniedTarget.user.id,
        reAuthenticatedAt: now,
        now,
      })
      .catch((caught: unknown) => caught)

    expect(deniedMergeError).toMatchObject({ code: UniAuthErrorCode.PolicyDenied })

    const allowedKit = createInMemoryAuthKit({
      policy: createDefaultAuthPolicy({ allowMergeAccounts: true, requireReAuthFor: [] }),
    })
    const source = await allowedKit.service.signIn({
      assertion: assertion({ providerUserId: 'source', email: 'source@example.com' }),
      now,
    })
    const target = await allowedKit.service.signIn({
      assertion: assertion({ providerUserId: 'target', email: 'target@example.com' }),
      now,
    })

    const merged = await allowedKit.service.mergeAccounts({
      sourceUserId: source.user.id,
      targetUserId: target.user.id,
      now,
    })

    expect(merged.movedIdentityIds).toEqual([source.identity.id])
    expect(merged.sourceUser.disabledAt).toEqual(now)
    expect(
      allowedKit.store
        .listIdentities()
        .filter((identity) => identity.id === source.identity.id)
        .map((identity) => identity.userId),
    ).toEqual([target.user.id])
    expect(
      allowedKit.store
        .listSessions()
        .filter((session) => session.userId === source.user.id)
        .map((session) => session.status),
    ).toEqual([SessionStatus.Revoked])
  })

  it('resolves assertions through a provider registry when requested', async () => {
    const { providerRegistry, service } = createInMemoryAuthKit()
    const provider = new StaticAuthProvider('telegram', {
      providerUserId: 'pending',
      displayName: 'Pending User',
    })

    provider.setAssertion({
      providerUserId: 'tg-1',
      displayName: 'Telegram User',
    })
    providerRegistry.register(provider)

    const result = await service.signIn({
      provider: 'telegram',
      finishInput: { payload: { initData: 'signed' } },
      now,
    })

    expect(result.identity.provider).toBe('telegram')
    expect(result.user.displayName).toBe('Telegram User')
  })
})
