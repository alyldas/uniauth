import { describe, expect, it } from 'vitest'
import {
  AuthIdentityStatus,
  CredentialType,
  DefaultAuthService,
  SessionStatus,
  UniauthError,
  UniauthErrorCode,
  VerificationPurpose,
  VerificationStatus,
  addSeconds,
  asAuditEventId,
  asCredentialId,
  asIdentityId,
  asSessionId,
  asUserId,
  asVerificationId,
  createAuthService,
  createDefaultAuthPolicy,
  generateOtpSecret,
  createRandomIdGenerator,
  createSequentialIdGenerator,
  generateSecret,
  hashSecret,
  invalidInput,
  isUniauthError,
  normalizeEmail,
  normalizePhone,
  normalizeTarget,
  systemClock,
  verifySecret,
  type AuthIdentity,
  type Credential,
  type ProviderIdentityAssertion,
  type Session,
  type User,
  type Verification,
} from '../src'
import { createInMemoryAuthKit, InMemoryAuthStore, StaticAuthProvider } from '../src/testing'

const now = new Date('2026-01-01T00:00:00.000Z')

function assertion(input: Partial<ProviderIdentityAssertion> = {}): ProviderIdentityAssertion {
  return {
    provider: input.provider ?? 'email',
    providerUserId: input.providerUserId ?? 'alice',
    ...(input.email ? { email: input.email } : {}),
    ...(input.emailVerified !== undefined ? { emailVerified: input.emailVerified } : {}),
    ...(input.phone ? { phone: input.phone } : {}),
    ...(input.phoneVerified !== undefined ? { phoneVerified: input.phoneVerified } : {}),
    ...(input.displayName ? { displayName: input.displayName } : {}),
    ...(input.metadata ? { metadata: input.metadata } : {}),
    ...(input.rawProfile ? { rawProfile: input.rawProfile } : {}),
  }
}

function user(id = 'user-1'): User {
  return {
    id: asUserId(id),
    createdAt: now,
    updatedAt: now,
  }
}

function identity(input: Partial<AuthIdentity> = {}): AuthIdentity {
  return {
    id: input.id ?? asIdentityId('identity-1'),
    userId: input.userId ?? asUserId('user-1'),
    provider: input.provider ?? 'email',
    providerUserId: input.providerUserId ?? 'alice',
    status: input.status ?? AuthIdentityStatus.Active,
    createdAt: input.createdAt ?? now,
    updatedAt: input.updatedAt ?? now,
    ...(input.email ? { email: input.email } : {}),
    ...(input.emailVerified !== undefined ? { emailVerified: input.emailVerified } : {}),
    ...(input.phone ? { phone: input.phone } : {}),
    ...(input.phoneVerified !== undefined ? { phoneVerified: input.phoneVerified } : {}),
    ...(input.disabledAt ? { disabledAt: input.disabledAt } : {}),
    ...(input.metadata ? { metadata: input.metadata } : {}),
  }
}

describe('coverage support paths', () => {
  it('covers public helper utilities and branded id casts', () => {
    const randomIds = createRandomIdGenerator()

    expect(randomIds.userId()).toMatch(/^usr_/)
    expect(randomIds.identityId()).toMatch(/^idn_/)
    expect(randomIds.credentialId()).toMatch(/^crd_/)
    expect(randomIds.verificationId()).toMatch(/^vrf_/)
    expect(randomIds.sessionId()).toMatch(/^ses_/)
    expect(randomIds.auditEventId()).toMatch(/^aud_/)

    const sequentialIds = createSequentialIdGenerator('unit')

    expect(sequentialIds.userId()).toBe('unit_usr_1')
    expect(sequentialIds.identityId()).toBe('unit_idn_2')
    expect(sequentialIds.credentialId()).toBe('unit_crd_3')
    expect(sequentialIds.verificationId()).toBe('unit_vrf_4')
    expect(sequentialIds.sessionId()).toBe('unit_ses_5')
    expect(sequentialIds.auditEventId()).toBe('unit_aud_6')

    expect(asUserId('usr')).toBe('usr')
    expect(asIdentityId('idn')).toBe('idn')
    expect(asCredentialId('crd')).toBe('crd')
    expect(asVerificationId('vrf')).toBe('vrf')
    expect(asSessionId('ses')).toBe('ses')
    expect(asAuditEventId('aud')).toBe('aud')

    expect(CredentialType.Password).toBe('password')
    expect(normalizeEmail(' Alice@Example.COM ')).toBe('alice@example.com')
    expect(normalizePhone(' +1 (555) 123-4567 ')).toBe('+15551234567')
    expect(normalizeTarget(' Alice@Example.COM ')).toBe('alice@example.com')
    expect(normalizeTarget(' +1 (555) 123-4567 ')).toBe('+15551234567')

    const generatedSecret = generateSecret(8)
    const generatedOtpSecret = generateOtpSecret()
    const secretHash = hashSecret('secret')

    expect(generatedSecret).toBeTypeOf('string')
    expect(generatedOtpSecret).toMatch(/^\d{6}$/)
    expect(verifySecret('secret', secretHash)).toBe(true)
    expect(verifySecret('secret', 'plaintext')).toBe(false)
    expect(verifySecret('secret', 'sha256:short')).toBe(false)
    expect(verifySecret('wrong', secretHash)).toBe(false)
    expect(addSeconds(now, 5)).toEqual(new Date('2026-01-01T00:00:05.000Z'))
    expect(systemClock.now()).toBeInstanceOf(Date)
  })

  it('covers default policy and error helper branches', () => {
    const defaultPolicy = createDefaultAuthPolicy()
    const permissivePolicy = createDefaultAuthPolicy({
      allowAutoLink: true,
      allowMergeAccounts: true,
      reAuthMaxAgeSeconds: 1,
      requireReAuthFor: ['mergeAccounts'],
    })

    expect(
      defaultPolicy.canAutoLink({
        assertion: assertion(),
        targetUser: user(),
        existingIdentities: [],
      }),
    ).toBe(false)
    expect(
      defaultPolicy.canUnlinkIdentity({
        user: user(),
        identity: identity(),
        activeIdentityCount: 1,
      }),
    ).toBe(false)
    expect(
      defaultPolicy.canUnlinkIdentity({
        user: user(),
        identity: identity(),
        activeIdentityCount: 2,
      }),
    ).toBe(true)
    expect(
      defaultPolicy.canMergeUsers({
        sourceUser: user('source'),
        targetUser: user('target'),
        sourceIdentityCount: 1,
      }),
    ).toBe(false)
    expect(
      defaultPolicy.requiresReAuth({
        action: 'link',
        userId: asUserId('user-1'),
        now,
      }),
    ).toBe(false)
    expect(
      defaultPolicy.requiresReAuth({
        action: 'mergeAccounts',
        userId: asUserId('user-1'),
        now,
      }),
    ).toBe(true)
    expect(
      defaultPolicy.requiresReAuth({
        action: 'mergeAccounts',
        userId: asUserId('user-1'),
        now,
        reAuthenticatedAt: now,
      }),
    ).toBe(false)
    expect(
      permissivePolicy.requiresReAuth({
        action: 'mergeAccounts',
        userId: asUserId('user-1'),
        now,
        reAuthenticatedAt: new Date('2025-12-31T23:59:58.000Z'),
      }),
    ).toBe(true)
    expect(
      permissivePolicy.canAutoLink({
        assertion: assertion(),
        targetUser: user(),
        existingIdentities: [],
      }),
    ).toBe(true)
    expect(
      permissivePolicy.canMergeUsers({
        sourceUser: user('source'),
        targetUser: user('target'),
        sourceIdentityCount: 1,
      }),
    ).toBe(true)

    const error = new UniauthError(UniauthErrorCode.InvalidInput, 'Invalid.', { field: 'email' })

    expect(error.details).toEqual({ field: 'email' })
    expect(isUniauthError(error)).toBe(true)
    expect(isUniauthError(new Error('nope'))).toBe(false)
    expect(invalidInput().message).toBe('Invalid auth input.')
  })

  it('covers direct in-memory repository success and failure paths', async () => {
    const store = new InMemoryAuthStore()
    const createdUser = await store.userRepo.create(user())

    expect(await store.userRepo.findById(createdUser.id)).toBe(createdUser)
    expect(await store.userRepo.update(createdUser.id, { displayName: 'Alice' })).toMatchObject({
      displayName: 'Alice',
    })
    expect(
      await store.userRepo
        .update(asUserId('missing'), { displayName: 'Missing' })
        .catch((caught: unknown) => caught),
    ).toMatchObject({
      code: UniauthErrorCode.UserNotFound,
    })

    const emailIdentity = await store.identityRepo.create(
      identity({
        email: 'alice@example.com',
        emailVerified: true,
        phone: '+15551234567',
        phoneVerified: true,
      }),
    )
    const secondIdentity = await store.identityRepo.create(
      identity({
        id: asIdentityId('identity-2'),
        provider: 'oauth',
        providerUserId: 'oauth-alice',
      }),
    )

    expect(await store.identityRepo.findById(emailIdentity.id)).toBe(emailIdentity)
    expect(await store.identityRepo.findByProviderUserId('email', 'alice')).toBe(emailIdentity)
    expect(await store.identityRepo.findByProviderUserId('missing', 'missing')).toBeUndefined()
    expect(await store.identityRepo.findByVerifiedEmail(' Alice@Example.com ')).toEqual([
      emailIdentity,
    ])
    expect(await store.identityRepo.findByVerifiedPhone(' +1 (555) 123-4567 ')).toEqual([
      emailIdentity,
    ])
    expect(await store.identityRepo.listByUserId(createdUser.id)).toHaveLength(2)
    expect(
      await store.identityRepo.create(emailIdentity).catch((caught: unknown) => caught),
    ).toMatchObject({
      code: UniauthErrorCode.IdentityAlreadyLinked,
    })
    expect(
      await store.identityRepo
        .update(secondIdentity.id, {
          provider: emailIdentity.provider,
          providerUserId: emailIdentity.providerUserId,
        })
        .catch((caught: unknown) => caught),
    ).toMatchObject({ code: UniauthErrorCode.IdentityAlreadyLinked })
    expect(
      await store.identityRepo
        .update(asIdentityId('missing'), {})
        .catch((caught: unknown) => caught),
    ).toMatchObject({
      code: UniauthErrorCode.IdentityNotFound,
    })
    expect(
      await store.identityRepo.update(secondIdentity.id, { providerUserId: 'oauth-alice-2' }),
    ).toMatchObject({
      providerUserId: 'oauth-alice-2',
    })

    const credential: Credential = {
      id: asCredentialId('credential-1'),
      userId: createdUser.id,
      type: CredentialType.Password,
      secretHash: hashSecret('password'),
      createdAt: now,
      updatedAt: now,
    }

    expect(await store.credentialRepo.findById(credential.id)).toBeUndefined()
    expect(await store.credentialRepo.create(credential)).toBe(credential)
    expect(await store.credentialRepo.findById(credential.id)).toBe(credential)
    expect(await store.credentialRepo.listByUserId(createdUser.id)).toEqual([credential])
    expect(await store.credentialRepo.update(credential.id, { disabledAt: now })).toMatchObject({
      disabledAt: now,
    })
    expect(
      await store.credentialRepo
        .update(asCredentialId('missing'), {})
        .catch((caught: unknown) => caught),
    ).toMatchObject({
      code: UniauthErrorCode.InvalidInput,
    })

    const verification: Verification = {
      id: asVerificationId('verification-1'),
      purpose: VerificationPurpose.Link,
      target: 'alice@example.com',
      secretHash: hashSecret('123456'),
      status: VerificationStatus.Pending,
      createdAt: now,
      expiresAt: addSeconds(now, 60),
    }

    expect(await store.verificationRepo.findById(verification.id)).toBeUndefined()
    expect(await store.verificationRepo.create(verification)).toBe(verification)
    expect(await store.verificationRepo.findById(verification.id)).toBe(verification)
    expect(
      await store.verificationRepo.update(verification.id, { status: VerificationStatus.Consumed }),
    ).toMatchObject({
      status: VerificationStatus.Consumed,
    })
    expect(
      await store.verificationRepo
        .update(asVerificationId('missing'), {})
        .catch((caught: unknown) => caught),
    ).toMatchObject({
      code: UniauthErrorCode.VerificationNotFound,
    })

    const session: Session = {
      id: asSessionId('session-1'),
      userId: createdUser.id,
      status: SessionStatus.Active,
      createdAt: now,
      expiresAt: addSeconds(now, 60),
    }

    expect(await store.sessionRepo.findById(session.id)).toBeUndefined()
    expect(await store.sessionRepo.create(session)).toBe(session)
    expect(await store.sessionRepo.findById(session.id)).toBe(session)
    expect(await store.sessionRepo.listByUserId(createdUser.id)).toEqual([session])
    expect(
      await store.sessionRepo.update(session.id, { status: SessionStatus.Revoked }),
    ).toMatchObject({
      status: SessionStatus.Revoked,
    })
    expect(
      await store.sessionRepo.update(asSessionId('missing'), {}).catch((caught: unknown) => caught),
    ).toMatchObject({
      code: UniauthErrorCode.SessionNotFound,
    })

    await store.auditLogRepo.append({
      id: asAuditEventId('audit-1'),
      type: 'auth.policy_denied',
      occurredAt: now,
    })

    expect(store.listUsers()).toHaveLength(1)
    expect(store.listIdentities()).toHaveLength(2)
    expect(store.listVerifications()).toHaveLength(1)
    expect(store.listSessions()).toHaveLength(1)
    expect(store.listAuditEvents()).toHaveLength(1)
  })

  it('covers uncommon auth-service branches and failure modes', async () => {
    const defaultStore = new InMemoryAuthStore()
    const defaultService = new DefaultAuthService({ repos: defaultStore })
    const first = await defaultService.signIn({
      assertion: assertion({
        provider: '  email  ',
        providerUserId: ' alice ',
        email: ' Alice@Example.com ',
        emailVerified: true,
        phone: ' +1 (555) 123-4567 ',
        phoneVerified: true,
        displayName: ' Alice ',
        metadata: { source: 'test' },
        rawProfile: { id: 1 },
      }),
    })

    expect(first.user.id).toMatch(/^usr_/)
    expect(first.user.email).toBe('alice@example.com')
    expect(first.user.phone).toBe('+15551234567')
    expect(first.identity.metadata).toEqual({ source: 'test' })

    await defaultService.signIn({
      assertion: assertion({
        provider: 'email',
        providerUserId: 'alice',
      }),
      metadata: { mode: 'exact' },
      sessionExpiresAt: addSeconds(now, 30),
    })
    await defaultService.signIn({
      assertion: assertion({
        provider: 'email',
        providerUserId: 'charlie',
        email: 'charlie@example.com',
        emailVerified: true,
      }),
      metadata: { mode: 'new-user-options' },
      sessionExpiresAt: addSeconds(now, 30),
    })

    const explicitSession = await defaultService.createSession({
      userId: first.user.id,
      expiresAt: addSeconds(now, 5),
      metadata: { manual: true },
      now,
    })

    expect(explicitSession.metadata).toEqual({ manual: true })
    expect(await defaultService.getUserIdentities(first.user.id)).toHaveLength(1)
    await defaultService.revokeSession(explicitSession.id)
    expect(
      await defaultService.revokeSession(asSessionId('missing')).catch((caught: unknown) => caught),
    ).toMatchObject({
      code: UniauthErrorCode.SessionNotFound,
    })

    expect(
      await defaultService
        .link({
          userId: first.user.id,
          assertion: assertion({
            provider: 'email',
            providerUserId: 'alice',
          }),
          now,
        })
        .then((result) => result.linked),
    ).toBe(false)

    const linked = await defaultService.link({
      userId: first.user.id,
      assertion: assertion({
        provider: 'oauth',
        providerUserId: 'alice-oauth',
        email: 'alice@example.com',
        metadata: { linked: true },
      }),
      metadata: { action: 'manual-link' },
      now,
    })

    expect(linked.linked).toBe(true)
    const clockLinked = await defaultService.link({
      userId: first.user.id,
      assertion: assertion({
        provider: 'clock',
        providerUserId: 'clock-link',
      }),
    })

    await defaultService.unlink({
      userId: first.user.id,
      identityId: clockLinked.identity.id,
    })
    await defaultService.unlink({
      userId: first.user.id,
      identityId: linked.identity.id,
      metadata: { action: 'unlink' },
      now,
    })
    expect(
      await defaultService
        .unlink({ userId: first.user.id, identityId: linked.identity.id, now })
        .catch((caught: unknown) => caught),
    ).toMatchObject({
      code: UniauthErrorCode.IdentityNotFound,
    })

    const second = await defaultService.signIn({
      assertion: assertion({
        provider: 'email',
        providerUserId: 'bob',
        email: 'bob@example.com',
        emailVerified: true,
      }),
      now,
    })

    expect(
      await defaultService
        .unlink({ userId: second.user.id, identityId: first.identity.id, now })
        .catch((caught: unknown) => caught),
    ).toMatchObject({
      code: UniauthErrorCode.IdentityNotFound,
    })
    expect(
      await defaultService
        .mergeAccounts({
          sourceUserId: second.user.id,
          targetUserId: second.user.id,
          now,
        })
        .catch((caught: unknown) => caught),
    ).toMatchObject({ code: UniauthErrorCode.InvalidInput })

    await defaultStore.userRepo.update(second.user.id, { disabledAt: now })
    expect(
      await defaultService.getUserIdentities(second.user.id).catch((caught: unknown) => caught),
    ).toMatchObject({
      code: UniauthErrorCode.UserNotFound,
    })
  })

  it('covers provider resolution, re-auth, verification, auto-link, and policy edge cases', async () => {
    const noRegistryService = createAuthService({ repos: new InMemoryAuthStore() })

    expect(
      await noRegistryService
        .signIn({ provider: 'missing', finishInput: {}, now })
        .catch((caught: unknown) => caught),
    ).toMatchObject({
      code: UniauthErrorCode.ProviderNotFound,
    })
    expect(
      await noRegistryService.signIn({ now }).catch((caught: unknown) => caught),
    ).toMatchObject({
      code: UniauthErrorCode.InvalidInput,
    })
    expect(
      await noRegistryService
        .signIn({
          assertion: assertion({ provider: '   ', providerUserId: 'user' }),
          now,
        })
        .catch((caught: unknown) => caught),
    ).toMatchObject({ code: UniauthErrorCode.InvalidInput })

    const kit = createInMemoryAuthKit({
      policy: createDefaultAuthPolicy({
        allowAutoLink: true,
        allowMergeAccounts: true,
        requireReAuthFor: ['link', 'mergeAccounts', 'unlink'],
        reAuthMaxAgeSeconds: 60,
      }),
      clock: { now: () => now },
      sessionTtlSeconds: 5,
      verificationTtlSeconds: 5,
    })
    const provider = new StaticAuthProvider('phone', {
      providerUserId: 'phone-user',
      phone: ' +1 (555) 123-4567 ',
      phoneVerified: true,
    })

    expect(await provider.start()).toEqual({ kind: 'noop' })
    kit.providerRegistry.register(provider)

    expect(
      await kit.service
        .signIn({ provider: 'missing', finishInput: {}, now })
        .catch((caught: unknown) => caught),
    ).toMatchObject({
      code: UniauthErrorCode.ProviderNotFound,
    })

    const phoneUser = await kit.service.signIn({
      provider: 'phone',
      finishInput: { payload: { signed: true } },
      now,
    })
    const autoLinked = await kit.service.signIn({
      assertion: assertion({
        provider: 'oauth',
        providerUserId: 'phone-oauth',
        phone: '+15551234567',
        phoneVerified: true,
      }),
      metadata: { mode: 'phone-auto-link' },
      sessionExpiresAt: addSeconds(now, 30),
      now,
    })

    expect(autoLinked.user.id).toBe(phoneUser.user.id)

    expect(
      await kit.service
        .link({
          userId: phoneUser.user.id,
          assertion: assertion({
            provider: 'passkey',
            providerUserId: 'passkey-1',
          }),
          now,
        })
        .catch((caught: unknown) => caught),
    ).toMatchObject({ code: UniauthErrorCode.ReAuthRequired })

    const passkey = await kit.service.link({
      userId: phoneUser.user.id,
      assertion: assertion({
        provider: 'passkey',
        providerUserId: 'passkey-1',
      }),
      reAuthenticatedAt: now,
      now,
    })

    expect(
      await kit.service
        .unlink({
          userId: phoneUser.user.id,
          identityId: passkey.identity.id,
          reAuthenticatedAt: new Date('2025-12-31T23:00:00.000Z'),
          now,
        })
        .catch((caught: unknown) => caught),
    ).toMatchObject({ code: UniauthErrorCode.ReAuthRequired })

    const verification = await kit.service.createVerification({
      purpose: VerificationPurpose.ReAuth,
      target: ' +1 (555) 123-4567 ',
      metadata: { channel: 'sms' },
      now,
    })
    const clockVerification = await kit.service.createVerification({
      purpose: VerificationPurpose.SignIn,
      target: 'clock@example.com',
    })
    const clockSession = await kit.service.createSession({
      userId: phoneUser.user.id,
    })

    expect(verification.secret).toBeTypeOf('string')
    expect(verification.verification.target).toBe('+15551234567')
    expect(verification.verification.metadata).toEqual({ channel: 'sms' })
    expect(clockSession.expiresAt).toEqual(addSeconds(now, 5))
    expect(
      await kit.service.consumeVerification({
        verificationId: clockVerification.verification.id,
        secret: clockVerification.secret,
      }),
    ).toMatchObject({ status: VerificationStatus.Consumed })
    expect(
      await kit.service
        .consumeVerification({ verificationId: asVerificationId('missing'), secret: 'x', now })
        .catch((caught: unknown) => caught),
    ).toMatchObject({
      code: UniauthErrorCode.VerificationNotFound,
    })
    expect(
      await kit.service
        .consumeVerification({
          verificationId: verification.verification.id,
          secret: verification.secret,
          now: addSeconds(now, 5),
        })
        .catch((caught: unknown) => caught),
    ).toMatchObject({ code: UniauthErrorCode.VerificationExpired })

    const deniedKit = createInMemoryAuthKit({
      policy: {
        canAutoLink: () => false,
        canMergeUsers: () => false,
        canUnlinkIdentity: () => false,
        requiresReAuth: () => false,
      },
    })
    const deniedUser = await deniedKit.service.signIn({
      assertion: assertion({
        provider: 'email',
        providerUserId: 'denied',
        email: 'denied@example.com',
      }),
      now,
    })
    const deniedIdentity = await deniedKit.service.link({
      userId: deniedUser.user.id,
      assertion: assertion({ provider: 'oauth', providerUserId: 'denied-oauth' }),
      now,
    })

    expect(
      await deniedKit.service
        .unlink({ userId: deniedUser.user.id, identityId: deniedIdentity.identity.id, now })
        .catch((caught: unknown) => caught),
    ).toMatchObject({ code: UniauthErrorCode.PolicyDenied })

    const malformedKit = createInMemoryAuthKit({
      policy: createDefaultAuthPolicy({ allowAutoLink: true }),
    })
    await malformedKit.store.userRepo.create(user('disabled-user'))
    await malformedKit.store.userRepo.update(asUserId('disabled-user'), { disabledAt: now })
    await malformedKit.store.identityRepo.create(
      identity({
        id: asIdentityId('disabled-target-identity'),
        userId: asUserId('disabled-user'),
        provider: 'email',
        providerUserId: 'disabled-target',
        email: 'disabled@example.com',
        emailVerified: true,
      }),
    )
    await malformedKit.store.identityRepo.create(
      identity({
        id: asIdentityId('disabled-email-identity'),
        userId: asUserId('disabled-user'),
        provider: 'email',
        providerUserId: 'disabled-email',
        email: 'inactive@example.com',
        emailVerified: true,
        disabledAt: now,
      }),
    )
    await malformedKit.store.identityRepo.create(
      identity({
        id: asIdentityId('disabled-phone-identity'),
        userId: asUserId('disabled-user'),
        provider: 'phone',
        providerUserId: 'disabled-phone',
        phone: '+15559990000',
        phoneVerified: true,
        disabledAt: now,
      }),
    )
    await malformedKit.store.identityRepo.create({
      id: asIdentityId('missing-user-identity'),
      userId: undefined as unknown as User['id'],
      provider: 'email',
      providerUserId: 'missing-user',
      email: 'missing-user@example.com',
      emailVerified: true,
      status: AuthIdentityStatus.Active,
      createdAt: now,
      updatedAt: now,
    })

    const inactiveEmailTarget = await malformedKit.service.signIn({
      assertion: assertion({
        provider: 'oauth',
        providerUserId: 'inactive-email-oauth',
        email: 'inactive@example.com',
        emailVerified: true,
      }),
      now,
    })
    const inactivePhoneTarget = await malformedKit.service.signIn({
      assertion: assertion({
        provider: 'oauth',
        providerUserId: 'inactive-phone-oauth',
        phone: '+15559990000',
        phoneVerified: true,
      }),
      now,
    })

    expect(inactiveEmailTarget.isNewUser).toBe(true)
    expect(inactivePhoneTarget.isNewUser).toBe(true)

    const mergeKit = createInMemoryAuthKit({
      policy: createDefaultAuthPolicy({ allowMergeAccounts: true, requireReAuthFor: [] }),
      clock: { now: () => now },
    })
    const source = await mergeKit.service.signIn({
      assertion: assertion({ provider: 'email', providerUserId: 'source' }),
      now,
    })
    const target = await mergeKit.service.signIn({
      assertion: assertion({ provider: 'email', providerUserId: 'target' }),
      now,
    })
    const nonActiveSourceSession = await mergeKit.service.createSession({
      userId: source.user.id,
      now,
    })

    await mergeKit.service.revokeSession(nonActiveSourceSession.id)
    expect(
      await mergeKit.service.mergeAccounts({
        sourceUserId: source.user.id,
        targetUserId: target.user.id,
      }),
    ).toMatchObject({ movedIdentityIds: [source.identity.id] })

    const disabledTarget = await malformedKit.service.signIn({
      assertion: assertion({
        provider: 'oauth',
        providerUserId: 'disabled-oauth',
        email: 'disabled@example.com',
        emailVerified: true,
      }),
      now,
    })
    const missingUserTarget = await malformedKit.service.signIn({
      assertion: assertion({
        provider: 'oauth',
        providerUserId: 'missing-user-oauth',
        email: 'missing-user@example.com',
        emailVerified: true,
      }),
      now,
    })

    expect(disabledTarget.isNewUser).toBe(true)
    expect(missingUserTarget.isNewUser).toBe(true)
  })
})
