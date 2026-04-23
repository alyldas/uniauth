import { describe, expect, it } from 'vitest'
import {
  AuthIdentityStatus,
  AuthPolicyAction,
  CredentialType,
  DefaultAuthService,
  OtpChannel,
  PASSWORD_PROVIDER_ID,
  RateLimitAction,
  SessionStatus,
  UniAuthErrorCode,
  VerificationPurpose,
  VerificationStatus,
  addSeconds,
  asCredentialId,
  asIdentityId,
  asVerificationId,
  createDefaultAuthPolicy,
  type EmailSender,
} from '../src'
import { InMemoryAuthStore, InMemoryRateLimiter, createInMemoryAuthKit } from '../src/testing'
import { assertion, now, rateLimitKey, user } from './helpers.js'

describe('password credentials', () => {
  it('sets a password credential and signs in without exposing the password hash as plaintext', async () => {
    const { service, store } = createInMemoryAuthKit({
      clock: { now: () => now },
    })
    const initial = await service.signIn({
      assertion: assertion({
        provider: 'oauth',
        providerUserId: 'alice-oauth',
        email: 'alice@example.com',
        emailVerified: true,
      }),
      now,
    })

    const credential = await service.setPassword({
      userId: initial.user.id,
      email: ' Alice@Example.com ',
      password: 'correct horse battery staple',
      metadata: { source: 'settings' },
    })
    const result = await service.signInWithPassword({
      email: 'alice@example.com',
      password: 'correct horse battery staple',
      sessionExpiresAt: addSeconds(now, 60),
      metadata: { flow: 'password' },
    })

    expect(credential.type).toBe(CredentialType.Password)
    expect(credential.subject).toBe('alice@example.com')
    expect(credential.passwordHash).not.toBe('correct horse battery staple')
    expect(credential.passwordHash).toMatch(/^test-password:sha256:/)
    expect(result.user.id).toBe(initial.user.id)
    expect(result.identity.provider).toBe(PASSWORD_PROVIDER_ID)
    expect(result.session.status).toBe(SessionStatus.Active)
    expect(result.session.expiresAt).toEqual(addSeconds(now, 60))
    expect(store.listCredentials()).toEqual([
      expect.objectContaining({
        id: credential.id,
        subject: 'alice@example.com',
        metadata: { source: 'settings' },
      }),
    ])
    expect(store.listIdentities()).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          provider: PASSWORD_PROVIDER_ID,
          providerUserId: 'alice@example.com',
          emailVerified: true,
        }),
      ]),
    )
  })

  it('uses neutral errors for invalid password sign-in state', async () => {
    const { service, store } = createInMemoryAuthKit()
    const initial = await service.signIn({
      assertion: assertion({ provider: 'oauth', providerUserId: 'alice-oauth' }),
      now,
    })
    await service.setPassword({
      userId: initial.user.id,
      email: 'alice@example.com',
      password: 'correct-password',
      now,
    })
    const wrongPasswordError = await service
      .signInWithPassword({
        email: 'alice@example.com',
        password: 'wrong-password',
        now,
      })
      .catch((caught: unknown) => caught)
    const missingEmailError = await service
      .signInWithPassword({
        email: 'missing@example.com',
        password: 'correct-password',
        now,
      })
      .catch((caught: unknown) => caught)
    const disabledUser = await service.signIn({
      assertion: assertion({
        provider: 'oauth',
        providerUserId: 'disabled-oauth',
        email: 'disabled@example.com',
        emailVerified: true,
      }),
      now,
    })
    await service.setPassword({
      userId: disabledUser.user.id,
      email: 'disabled@example.com',
      password: 'disabled-password',
      now,
    })
    await store.userRepo.update(disabledUser.user.id, { disabledAt: now })
    const disabledUserError = await service
      .signInWithPassword({
        email: 'disabled@example.com',
        password: 'disabled-password',
        now,
      })
      .catch((caught: unknown) => caught)

    expect(wrongPasswordError).toMatchObject({ code: UniAuthErrorCode.InvalidCredentials })
    expect(missingEmailError).toMatchObject({ code: UniAuthErrorCode.InvalidCredentials })
    expect(disabledUserError).toMatchObject({ code: UniAuthErrorCode.InvalidCredentials })
  })

  it('changes a password only after the current password is verified', async () => {
    const { service } = createInMemoryAuthKit({
      policy: createDefaultAuthPolicy({
        requireReAuthFor: [AuthPolicyAction.ChangePassword],
      }),
      clock: { now: () => now },
    })
    const initial = await service.signIn({
      assertion: assertion({ provider: 'oauth', providerUserId: 'alice-oauth' }),
      now,
    })
    await service.setPassword({
      userId: initial.user.id,
      email: 'alice@example.com',
      password: 'old-password',
      now,
    })

    const reAuthError = await service
      .changePassword({
        userId: initial.user.id,
        currentPassword: 'old-password',
        newPassword: 'new-password',
        now,
      })
      .catch((caught: unknown) => caught)
    const wrongCurrentError = await service
      .changePassword({
        userId: initial.user.id,
        currentPassword: 'wrong-password',
        newPassword: 'new-password',
        reAuthenticatedAt: now,
        now,
      })
      .catch((caught: unknown) => caught)
    const changed = await service.changePassword({
      userId: initial.user.id,
      currentPassword: 'old-password',
      newPassword: 'new-password',
      reAuthenticatedAt: now,
      metadata: { source: 'settings' },
    })
    const oldPasswordError = await service
      .signInWithPassword({
        email: 'alice@example.com',
        password: 'old-password',
        now,
      })
      .catch((caught: unknown) => caught)
    const signedIn = await service.signInWithPassword({
      email: 'alice@example.com',
      password: 'new-password',
      now,
    })

    expect(reAuthError).toMatchObject({ code: UniAuthErrorCode.ReAuthRequired })
    expect(wrongCurrentError).toMatchObject({ code: UniAuthErrorCode.InvalidCredentials })
    expect(changed.metadata).toEqual({ source: 'settings' })
    expect(oldPasswordError).toMatchObject({ code: UniAuthErrorCode.InvalidCredentials })
    expect(signedIn.user.id).toBe(initial.user.id)
  })

  it('preserves last-sign-in-method protection for password identities', async () => {
    const { service, store } = createInMemoryAuthKit()
    const createdUser = await store.userRepo.create(user('password-user'))
    await service.setPassword({
      userId: createdUser.id,
      email: 'password@example.com',
      password: 'password',
      now,
    })
    const passwordIdentity = store
      .listIdentities()
      .find((identity) => identity.provider === PASSWORD_PROVIDER_ID)

    const unlinkError = await service
      .unlink({
        userId: createdUser.id,
        identityId: passwordIdentity?.id ?? asIdentityId('missing'),
        now,
      })
      .catch((caught: unknown) => caught)

    expect(unlinkError).toMatchObject({ code: UniAuthErrorCode.LastIdentity })
  })

  it('guards password setup conflicts and required infrastructure', async () => {
    const { service } = createInMemoryAuthKit({
      policy: createDefaultAuthPolicy({ requireReAuthFor: [AuthPolicyAction.SetPassword] }),
    })
    const first = await service.signIn({
      assertion: assertion({ provider: 'oauth', providerUserId: 'alice-oauth' }),
      now,
    })
    const second = await service.signIn({
      assertion: assertion({ provider: 'oauth', providerUserId: 'bob-oauth' }),
      now,
    })
    const missingHasherService = new DefaultAuthService({ repos: new InMemoryAuthStore() })

    const reAuthError = await service
      .setPassword({
        userId: first.user.id,
        email: 'alice@example.com',
        password: 'alice-password',
        now,
      })
      .catch((caught: unknown) => caught)
    await service.setPassword({
      userId: first.user.id,
      email: 'alice@example.com',
      password: 'alice-password',
      reAuthenticatedAt: now,
      now,
    })
    const updated = await service.setPassword({
      userId: first.user.id,
      email: 'alice@example.com',
      password: 'alice-password-2',
      reAuthenticatedAt: now,
      now,
    })
    const conflictError = await service
      .setPassword({
        userId: second.user.id,
        email: 'alice@example.com',
        password: 'bob-password',
        reAuthenticatedAt: now,
        now,
      })
      .catch((caught: unknown) => caught)
    const emailChangeError = await service
      .setPassword({
        userId: first.user.id,
        email: 'alice-new@example.com',
        password: 'alice-password',
        reAuthenticatedAt: now,
        now,
      })
      .catch((caught: unknown) => caught)
    const missingHasherError = await missingHasherService
      .signInWithPassword({
        email: 'alice@example.com',
        password: 'alice-password',
        now,
      })
      .catch((caught: unknown) => caught)
    const blankEmailError = await service
      .setPassword({
        userId: first.user.id,
        email: ' ',
        password: 'password',
        reAuthenticatedAt: now,
        now,
      })
      .catch((caught: unknown) => caught)
    const blankPasswordError = await service
      .signInWithPassword({
        email: 'alice@example.com',
        password: '',
        now,
      })
      .catch((caught: unknown) => caught)

    expect(updated.passwordHash).not.toBe('alice-password')
    expect(reAuthError).toMatchObject({ code: UniAuthErrorCode.ReAuthRequired })
    expect(conflictError).toMatchObject({ code: UniAuthErrorCode.CredentialAlreadyExists })
    expect(emailChangeError).toMatchObject({ code: UniAuthErrorCode.InvalidInput })
    expect(missingHasherError).toMatchObject({ code: UniAuthErrorCode.InvalidInput })
    expect(blankEmailError).toMatchObject({ code: UniAuthErrorCode.InvalidInput })
    expect(blankPasswordError).toMatchObject({ code: UniAuthErrorCode.InvalidInput })
  })

  it('starts and finishes password recovery with consume-once verification semantics', async () => {
    const { service, store, emailSender } = createInMemoryAuthKit({
      clock: { now: () => now },
    })
    const initial = await service.signIn({
      assertion: assertion({ provider: 'oauth', providerUserId: 'alice-oauth' }),
      now,
    })
    await service.setPassword({
      userId: initial.user.id,
      email: 'alice@example.com',
      password: 'old-password',
      now,
    })

    const recovery = await service.startEmailPasswordRecovery({
      email: 'Alice@Example.com',
      secret: 'recovery-secret',
      ttlSeconds: 300,
      createLink: ({ verificationId, secret }) =>
        `https://app.example.test/auth/recovery?vid=${verificationId}&token=${secret}`,
    })
    const recovered = await service.finishEmailPasswordRecovery({
      verificationId: recovery.verificationId,
      secret: 'recovery-secret',
      newPassword: 'new-password',
      metadata: { source: 'recovery' },
    })
    const consumedAgainError = await service
      .finishEmailPasswordRecovery({
        verificationId: recovery.verificationId,
        secret: 'recovery-secret',
        newPassword: 'another-password',
      })
      .catch((caught: unknown) => caught)
    const signedIn = await service.signInWithPassword({
      email: 'alice@example.com',
      password: 'new-password',
      now,
    })

    expect(recovery.delivery).toBe(OtpChannel.Email)
    expect(recovery.expiresAt).toEqual(addSeconds(now, 300))
    expect(emailSender.listMessages()).toEqual([
      expect.objectContaining({
        to: 'alice@example.com',
        subject: 'Reset your password',
        metadata: {
          verificationId: recovery.verificationId,
          purpose: VerificationPurpose.Recovery,
          delivery: OtpChannel.Email,
          provider: PASSWORD_PROVIDER_ID,
        },
      }),
    ])
    expect(recovered.metadata).toEqual({ source: 'recovery' })
    expect(store.listVerifications()).toEqual([
      expect.objectContaining({
        id: recovery.verificationId,
        provider: PASSWORD_PROVIDER_ID,
        channel: OtpChannel.Email,
        status: VerificationStatus.Consumed,
      }),
    ])
    expect(consumedAgainError).toMatchObject({ code: UniAuthErrorCode.VerificationConsumed })
    expect(signedIn.user.id).toBe(initial.user.id)
  })

  it('keeps pending password recovery verifications when link creation or delivery fails', async () => {
    const linkKit = createInMemoryAuthKit()
    const linkError = await linkKit.service
      .startEmailPasswordRecovery({
        email: 'alice@example.com',
        secret: 'recovery-secret',
        createLink: () => {
          throw new Error('Link failed.')
        },
        now,
      })
      .catch((caught: unknown) => caught)

    expect(linkError).toBeInstanceOf(Error)
    expect(linkKit.emailSender.listMessages()).toHaveLength(0)
    expect(linkKit.store.listVerifications()).toEqual([
      expect.objectContaining({
        purpose: VerificationPurpose.Recovery,
        target: 'alice@example.com',
        provider: PASSWORD_PROVIDER_ID,
        channel: OtpChannel.Email,
        status: VerificationStatus.Pending,
      }),
    ])

    const deliveryStore = new InMemoryAuthStore()
    const failingEmailSender: EmailSender = {
      sendEmail: async () => {
        throw new Error('Delivery failed.')
      },
    }
    const deliveryService = new DefaultAuthService({
      repos: deliveryStore,
      emailSender: failingEmailSender,
    })
    const deliveryError = await deliveryService
      .startEmailPasswordRecovery({
        email: 'bob@example.com',
        secret: 'recovery-secret',
        createLink: ({ secret }) => `https://app.example.test/auth/recovery?token=${secret}`,
        now,
      })
      .catch((caught: unknown) => caught)

    expect(deliveryError).toBeInstanceOf(Error)
    expect(deliveryStore.listVerifications()).toEqual([
      expect.objectContaining({
        purpose: VerificationPurpose.Recovery,
        target: 'bob@example.com',
        provider: PASSWORD_PROVIDER_ID,
        channel: OtpChannel.Email,
        status: VerificationStatus.Pending,
      }),
    ])
  })

  it('keeps password recovery errors neutral for invalid account state', async () => {
    const { service, store } = createInMemoryAuthKit()
    const missingSenderService = new DefaultAuthService({ repos: new InMemoryAuthStore() })

    const missingSenderError = await missingSenderService
      .startEmailPasswordRecovery({
        email: 'alice@example.com',
        createLink: () => 'https://app.example.test/auth/recovery',
        now,
      })
      .catch((caught: unknown) => caught)
    const unknownRecovery = await service.startEmailPasswordRecovery({
      email: 'unknown@example.com',
      secret: 'unknown-secret',
      createLink: () => 'https://app.example.test/auth/recovery',
      now,
    })
    await service.startEmailPasswordRecovery({
      email: 'generated@example.com',
      createLink: () => 'https://app.example.test/auth/recovery',
      now,
    })
    const unknownFinishError = await service
      .finishEmailPasswordRecovery({
        verificationId: unknownRecovery.verificationId,
        secret: 'unknown-secret',
        newPassword: 'new-password',
        now,
      })
      .catch((caught: unknown) => caught)
    const missingVerificationError = await service
      .finishEmailPasswordRecovery({
        verificationId: asVerificationId('missing'),
        secret: 'secret',
        newPassword: 'new-password',
        now,
      })
      .catch((caught: unknown) => caught)
    const otp = await service.startOtpChallenge({
      purpose: VerificationPurpose.SignIn,
      channel: OtpChannel.Email,
      target: 'alice@example.com',
      secret: '123456',
      now,
    })
    const otpAsRecoveryError = await service
      .finishEmailPasswordRecovery({
        verificationId: otp.verificationId,
        secret: '123456',
        newPassword: 'new-password',
        now,
      })
      .catch((caught: unknown) => caught)

    expect(missingSenderError).toMatchObject({ code: UniAuthErrorCode.InvalidInput })
    expect(unknownFinishError).toMatchObject({ code: UniAuthErrorCode.InvalidCredentials })
    expect(missingVerificationError).toMatchObject({
      code: UniAuthErrorCode.VerificationNotFound,
    })
    expect(otpAsRecoveryError).toMatchObject({ code: UniAuthErrorCode.InvalidInput })
    expect(store.listUsers()).toHaveLength(0)
    expect(store.listSessions()).toHaveLength(0)
  })

  it('rate-limits password sign-in and recovery attempts without account side effects', async () => {
    const rateLimiter = new InMemoryRateLimiter()
    const { service, store, emailSender } = createInMemoryAuthKit({ rateLimiter })
    const initial = await service.signIn({
      assertion: assertion({ provider: 'oauth', providerUserId: 'alice-oauth' }),
      now,
    })
    await service.setPassword({
      userId: initial.user.id,
      email: 'alice@example.com',
      password: 'password',
      now,
    })

    rateLimiter.setDecision(
      {
        action: RateLimitAction.PasswordSignIn,
        key: rateLimitKey(OtpChannel.Email, 'alice@example.com'),
      },
      { allowed: false, retryAfterSeconds: 30 },
    )
    const signInError = await service
      .signInWithPassword({
        email: 'alice@example.com',
        password: 'password',
        now,
      })
      .catch((caught: unknown) => caught)
    rateLimiter.setDecision(
      {
        action: RateLimitAction.PasswordRecoveryStart,
        key: rateLimitKey(OtpChannel.Email, 'alice@example.com'),
      },
      { allowed: false, retryAfterSeconds: 60 },
    )
    const recoveryStartError = await service
      .startEmailPasswordRecovery({
        email: 'alice@example.com',
        createLink: () => 'https://app.example.test/auth/recovery',
        now,
      })
      .catch((caught: unknown) => caught)

    rateLimiter.setDecision(
      {
        action: RateLimitAction.PasswordRecoveryStart,
        key: rateLimitKey(OtpChannel.Email, 'alice@example.com'),
      },
      { allowed: true },
    )
    const recovery = await service.startEmailPasswordRecovery({
      email: 'alice@example.com',
      secret: 'recovery-secret',
      createLink: () => 'https://app.example.test/auth/recovery',
      now,
    })
    rateLimiter.setDecision(
      {
        action: RateLimitAction.PasswordRecoveryFinish,
        key: rateLimitKey(OtpChannel.Email, recovery.verificationId),
      },
      { allowed: false, resetAt: now },
    )
    const recoveryFinishError = await service
      .finishEmailPasswordRecovery({
        verificationId: recovery.verificationId,
        secret: 'recovery-secret',
        newPassword: 'new-password',
        now,
      })
      .catch((caught: unknown) => caught)

    expect(signInError).toMatchObject({
      code: UniAuthErrorCode.RateLimited,
      details: { action: RateLimitAction.PasswordSignIn, retryAfterSeconds: 30 },
    })
    expect(recoveryStartError).toMatchObject({
      code: UniAuthErrorCode.RateLimited,
      details: { action: RateLimitAction.PasswordRecoveryStart, retryAfterSeconds: 60 },
    })
    expect(recoveryFinishError).toMatchObject({
      code: UniAuthErrorCode.RateLimited,
      details: { action: RateLimitAction.PasswordRecoveryFinish, resetAt: now.toISOString() },
    })
    expect(emailSender.listMessages()).toHaveLength(1)
    expect(store.listVerifications()).toEqual([
      expect.objectContaining({
        id: recovery.verificationId,
        status: VerificationStatus.Pending,
      }),
    ])
  })

  it('treats inconsistent password credential storage as invalid credentials', async () => {
    const { service, store, passwordHasher } = createInMemoryAuthKit()
    const createdUser = await store.userRepo.create(user('credential-user'))
    await store.credentialRepo.create({
      id: asCredentialId('credential-1'),
      userId: createdUser.id,
      type: CredentialType.Password,
      subject: 'orphan@example.com',
      passwordHash: await passwordHasher.hash('password'),
      createdAt: now,
      updatedAt: now,
    })

    const error = await service
      .signInWithPassword({
        email: 'orphan@example.com',
        password: 'password',
        now,
      })
      .catch((caught: unknown) => caught)

    expect(error).toMatchObject({ code: UniAuthErrorCode.InvalidCredentials })
  })

  it('rejects password setup when a password identity is already linked elsewhere', async () => {
    const { service, store } = createInMemoryAuthKit()
    const first = await store.userRepo.create(user('first-user'))
    const second = await store.userRepo.create(user('second-user'))
    await store.identityRepo.create({
      id: asIdentityId('password-identity'),
      userId: first.id,
      provider: PASSWORD_PROVIDER_ID,
      providerUserId: 'shared@example.com',
      status: AuthIdentityStatus.Active,
      createdAt: now,
      updatedAt: now,
    })

    const error = await service
      .setPassword({
        userId: second.id,
        email: 'shared@example.com',
        password: 'password',
        now,
      })
      .catch((caught: unknown) => caught)

    expect(error).toMatchObject({ code: UniAuthErrorCode.IdentityAlreadyLinked })
  })

  it('does not link a password identity when password hashing fails', async () => {
    const { service, store } = createInMemoryAuthKit({
      passwordHasher: {
        hash: async () => {
          throw new Error('hash failed')
        },
        verify: async () => false,
      },
    })
    const createdUser = await store.userRepo.create(user('hash-failure-user'))

    const error = await service
      .setPassword({
        userId: createdUser.id,
        email: 'hash-failure@example.com',
        password: 'password',
        now,
      })
      .catch((caught: unknown) => caught)

    expect(error).toMatchObject({ message: 'hash failed' })
    expect(store.listCredentials()).toHaveLength(0)
    expect(
      store.listIdentities().filter((identity) => identity.provider === PASSWORD_PROVIDER_ID),
    ).toHaveLength(0)
  })
})
