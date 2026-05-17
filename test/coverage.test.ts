import { describe, expect, it } from 'vitest'
import {
  AuthPolicyAction,
  UniAuthError,
  UniAuthErrorCode,
  addSeconds,
  asAuditEventId,
  asCredentialId,
  compatibilityAuthNormalizer,
  createAuthNormalizer,
  asIdentityId,
  asSessionId,
  asUserId,
  asVerificationId,
  createAuthService,
  createDefaultAuthPolicy,
  createHmacSecretHasher,
  createScryptSecretHasher,
  createRandomIdGenerator,
  createSequentialIdGenerator,
  generateOtpSecret,
  generateSecret,
  getUniAuthAttributionNotice,
  hashSecret,
  invalidCredentials,
  invalidInput,
  isUniAuthError,
  normalizeEmail,
  normalizePhone,
  normalizeTarget,
  systemClock,
  verifySecret,
} from '../src'
import { createAuthServiceRuntime } from '../src/application/runtime-defaults.js'
import { InMemoryAuthStore } from '../src/testing'
import { assertion, identity, now, user } from './helpers.js'

describe('public utility coverage', () => {
  it('covers helper utilities and branded id casts', async () => {
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

    expect(normalizeEmail(' Alice@Example.COM ')).toBe('alice@example.com')
    expect(normalizePhone(' +1 (555) 123-4567 ')).toBe('+15551234567')
    expect(normalizeTarget(' Alice@Example.COM ')).toBe('alice@example.com')
    expect(normalizeTarget(' +1 (555) 123-4567 ')).toBe('+15551234567')
    expect(normalizeTarget(' opaque-token ')).toBe('opaque-token')
    expect(normalizeTarget('   ')).toBe('')
    expect(() => normalizeEmail(123 as unknown as string)).toThrow('Email must be a string.')
    expect(() => normalizePhone(123 as unknown as string)).toThrow('Phone must be a string.')
    expect(() => normalizeTarget(123 as unknown as string)).toThrow('Target must be a string.')
    expect(compatibilityAuthNormalizer.normalizeEmail(' Alice@Example.COM ')).toBe(
      'alice@example.com',
    )
    expect(
      createAuthNormalizer({
        normalizeEmail: (email) => email.trim().toUpperCase(),
        normalizePhone: (phone) => phone.replace(/\s+/g, '').trim(),
        normalizeTarget: (target, helpers) =>
          target.includes('@')
            ? helpers.normalizeEmail(target)
            : `tel:${helpers.normalizePhone(target)}`,
      }).normalizeTarget(' 1 2 3 '),
    ).toBe('tel:123')
    expect(
      createAuthNormalizer({
        normalizeEmail: (email) => email.trim().toUpperCase(),
        normalizePhone: (phone) => phone.replace(/\s+/g, '').trim(),
      }).normalizeTarget(' Alice@Example.COM '),
    ).toBe('ALICE@EXAMPLE.COM')
    expect(
      createAuthNormalizer(Object.assign(Object.create(null), {})).normalizeTarget(' A@B '),
    ).toBe('a@b')
    expect(() => createAuthNormalizer(null as unknown as object)).toThrow(
      'Normalizer options must be a plain object.',
    )
    expect(() =>
      createAuthNormalizer({ normalizeEmail: 'email' as unknown as (value: string) => string }),
    ).toThrow('Email normalizer must be a function.')
    expect(() =>
      createAuthNormalizer({ normalizePhone: 'phone' as unknown as (value: string) => string }),
    ).toThrow('Phone normalizer must be a function.')
    expect(() =>
      createAuthNormalizer({
        normalizeTarget: 'target' as unknown as (value: string) => string,
      }),
    ).toThrow('Target normalizer must be a function.')

    const generatedSecret = generateSecret(8)
    const generatedOtpSecret = generateOtpSecret()
    const secretHash = hashSecret('secret')
    const hmacHasher = createHmacSecretHasher({ pepper: 'test-pepper' })
    const hmacHash = await hmacHasher.hash('123456')
    const defaultScryptHasher = createScryptSecretHasher()
    const defaultScryptHash = await defaultScryptHasher.hash('123456')
    const scryptHasher = createScryptSecretHasher({
      cost: 16,
      blockSize: 1,
      parallelization: 1,
      keyLength: 16,
      saltByteLength: 8,
      maxmem: 1024 * 1024,
    })
    const scryptHash = await scryptHasher.hash('123456')

    expect(generatedSecret).toBeTypeOf('string')
    expect(generatedOtpSecret).toMatch(/^\d{6}$/)
    expect(() => generateSecret(0)).toThrow('Secret byte length must be a positive integer.')
    expect(() => generateSecret(1.5)).toThrow('Secret byte length must be a positive integer.')
    expect(() => generateOtpSecret(0)).toThrow('OTP secret length must be a positive integer.')
    expect(() => generateOtpSecret(1.5)).toThrow('OTP secret length must be a positive integer.')
    expect(verifySecret('secret', secretHash)).toBe(true)
    expect(verifySecret('secret', 'plaintext')).toBe(false)
    expect(verifySecret('secret', 'sha256:short')).toBe(false)
    expect(verifySecret('wrong', secretHash)).toBe(false)
    expect(verifySecret(123 as unknown as string, secretHash)).toBe(false)
    expect(verifySecret('secret', 123 as unknown as string)).toBe(false)
    expect(() => hashSecret(123 as unknown as string)).toThrow('Secret must be a string.')
    expect(hmacHash).toMatch(/^hmac-sha256:/)
    expect(await hmacHasher.verify('123456', hmacHash)).toBe(true)
    expect(await hmacHasher.verify('000000', hmacHash)).toBe(false)
    expect(await hmacHasher.verify('123456', secretHash)).toBe(false)
    expect(await hmacHasher.verify(123 as unknown as string, hmacHash)).toBe(false)
    expect(() => hmacHasher.hash(123 as unknown as string)).toThrow('Secret must be a string.')
    expect(defaultScryptHash).toMatch(/^scrypt:/)
    expect(await defaultScryptHasher.verify('123456', defaultScryptHash)).toBe(true)
    await expect(defaultScryptHasher.hash(123 as unknown as string)).rejects.toThrow(
      'Secret must be a string.',
    )
    expect(await defaultScryptHasher.verify(123 as unknown as string, defaultScryptHash)).toBe(
      false,
    )
    expect(await defaultScryptHasher.verify('123456', 123 as unknown as string)).toBe(false)
    expect(scryptHash).toMatch(/^scrypt:/)
    expect(await scryptHasher.verify('123456', scryptHash)).toBe(true)
    expect(await scryptHasher.verify('000000', scryptHash)).toBe(false)
    expect(await scryptHasher.verify('123456', secretHash)).toBe(false)
    expect(await scryptHasher.verify('123456', 'scrypt:bad')).toBe(false)
    expect(await scryptHasher.verify('123456', 'scrypt:0:8:1:32:c2FsdA:AQ')).toBe(false)
    expect(await scryptHasher.verify('123456', 'scrypt:16:8:1:32:c2FsdA:AQ')).toBe(false)
    expect(await scryptHasher.verify('123456', 'scrypt:1024:100000:1:32:c2FsdA:AQ')).toBe(false)
    expect(() => createHmacSecretHasher({ pepper: '' })).toThrow(
      'Secret hasher pepper is required.',
    )
    expect(() => createHmacSecretHasher({ pepper: '   ' })).toThrow(
      'Secret hasher pepper is required.',
    )
    expect(() => createHmacSecretHasher(undefined as unknown as { pepper: string })).toThrow(
      'Secret hasher pepper is required.',
    )
    expect(() => createScryptSecretHasher({ cost: 15 })).toThrow(
      'Scrypt cost must be a power of two.',
    )
    expect(() => createScryptSecretHasher({ blockSize: 0 })).toThrow(
      'Scrypt block size must be a positive integer.',
    )
    expect(() => createScryptSecretHasher({ parallelization: 0 })).toThrow(
      'Scrypt parallelization must be a positive integer.',
    )
    expect(() => createScryptSecretHasher({ keyLength: 0 })).toThrow(
      'Scrypt key length must be a positive integer.',
    )
    expect(() => createScryptSecretHasher({ saltByteLength: 0 })).toThrow(
      'Scrypt salt byte length must be a positive integer.',
    )
    expect(() => createScryptSecretHasher({ maxmem: 0 })).toThrow(
      'Scrypt maxmem must be a positive integer.',
    )
    expect(addSeconds(now, 5)).toEqual(new Date('2026-01-01T00:00:05.000Z'))
    expect(() => addSeconds(new Date(Number.NaN), 5)).toThrow('Date must be valid.')
    expect(() => addSeconds(now, Number.POSITIVE_INFINITY)).toThrow(
      'Seconds must be a finite number.',
    )
    expect(() => addSeconds(now, '5' as unknown as number)).toThrow(
      'Seconds must be a finite number.',
    )
    expect(systemClock.now()).toBeInstanceOf(Date)
    expect(() => getUniAuthAttributionNotice({ productName: 123 as unknown as string })).toThrow(
      'Attribution product name must be a string.',
    )
    expect(() => getUniAuthAttributionNotice(null as unknown as object)).toThrow(
      'Attribution notice options must be a plain object.',
    )
    expect(getUniAuthAttributionNotice(Object.assign(Object.create(null), {}))).toContain(
      'This product uses',
    )

    const store = new InMemoryAuthStore()
    const runtime = createAuthServiceRuntime({
      repos: {
        userRepo: store.userRepo,
        identityRepo: store.identityRepo,
        credentialRepo: store.credentialRepo,
        verificationRepo: store.verificationRepo,
        sessionRepo: store.sessionRepo,
        auditLogRepo: store.auditLogRepo,
      },
    })

    await expect(runtime.transaction.run(async () => 'immediate')).resolves.toBe('immediate')
    await expect(
      createAuthServiceRuntime({ repos: store }).transaction.run(async () => 'repository'),
    ).resolves.toBe('repository')
    expect(
      createAuthServiceRuntime(Object.assign(Object.create(null), { repos: store })).repos.userRepo,
    ).toBe(store.userRepo)
    expect(() =>
      createAuthServiceRuntime(null as unknown as Parameters<typeof createAuthServiceRuntime>[0]),
    ).toThrow('Auth service options must be a plain object.')
    expect(() =>
      createAuthServiceRuntime({
        repos: null as unknown as Parameters<typeof createAuthServiceRuntime>[0]['repos'],
      }),
    ).toThrow('Auth service repositories are required.')
    expect(() =>
      createAuthServiceRuntime({
        repos: {
          userRepo: { ...store.userRepo, update: undefined },
          identityRepo: store.identityRepo,
          credentialRepo: store.credentialRepo,
          verificationRepo: store.verificationRepo,
          sessionRepo: store.sessionRepo,
          auditLogRepo: store.auditLogRepo,
        } as unknown as Parameters<typeof createAuthServiceRuntime>[0]['repos'],
      }),
    ).toThrow('User repository update is required.')
    expect(() =>
      createAuthServiceRuntime({
        repos: {
          userRepo: store.userRepo,
          identityRepo: store.identityRepo,
          credentialRepo: store.credentialRepo,
          verificationRepo: store.verificationRepo,
          sessionRepo: store.sessionRepo,
          auditLogRepo: null,
        } as unknown as Parameters<typeof createAuthServiceRuntime>[0]['repos'],
      }),
    ).toThrow('Audit log repository is required.')
    expect(() =>
      createAuthServiceRuntime({
        repos: store,
        requireRateLimiter: true,
      }),
    ).toThrow('Rate limiter is required by auth service options.')
    expect(() =>
      createAuthServiceRuntime({
        repos: store,
        requirePasswordPolicy: true,
      }),
    ).toThrow('Password policy is required by auth service options.')
    expect(() =>
      createAuthService({
        repos: null as unknown as Parameters<typeof createAuthService>[0]['repos'],
      }),
    ).toThrow('Auth service repositories are required.')
  })

  it('covers default policy and error helper branches', () => {
    const defaultPolicy = createDefaultAuthPolicy()
    const permissivePolicy = createDefaultAuthPolicy({
      allowAutoLink: true,
      allowMergeAccounts: true,
      reAuthMaxAgeSeconds: 1,
      requireReAuthFor: [AuthPolicyAction.MergeAccounts],
    })

    expect(
      defaultPolicy.canAutoLink({
        assertion: assertion(),
        targetUser: user(),
        existingIdentities: [],
      }),
    ).toBe(false)
    expect(
      defaultPolicy.canLinkIdentity!({
        user: user(),
        assertion: assertion(),
      }),
    ).toBe(true)
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
        sourceIdentities: [],
        targetIdentities: [],
      }),
    ).toBe(false)
    expect(
      defaultPolicy.requiresReAuth({
        action: AuthPolicyAction.Link,
        userId: asUserId('user-1'),
        now,
      }),
    ).toBe(false)
    expect(
      defaultPolicy.requiresReAuth({
        action: AuthPolicyAction.MergeAccounts,
        userId: asUserId('user-1'),
        now,
      }),
    ).toBe(true)
    expect(
      defaultPolicy.requiresReAuth({
        action: AuthPolicyAction.MergeAccounts,
        userId: asUserId('user-1'),
        now,
        reAuthenticatedAt: now,
      }),
    ).toBe(false)
    expect(() =>
      defaultPolicy.requiresReAuth({
        action: AuthPolicyAction.MergeAccounts,
        userId: asUserId('user-1'),
        now,
        reAuthenticatedAt: addSeconds(now, 1),
      }),
    ).toThrow('Default auth policy re-auth timestamp cannot be in the future.')
    expect(
      permissivePolicy.requiresReAuth({
        action: AuthPolicyAction.MergeAccounts,
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
        sourceIdentities: [],
        targetIdentities: [],
      }),
    ).toBe(true)
    expect(
      createDefaultAuthPolicy(Object.assign(Object.create(null), {})).canAutoLink({
        assertion: assertion(),
        targetUser: user(),
        existingIdentities: [],
      }),
    ).toBe(false)
    expect(() => createDefaultAuthPolicy(null as unknown as object)).toThrow(
      'Default auth policy options must be a plain object.',
    )
    expect(() =>
      createDefaultAuthPolicy({ requireReAuthFor: [''] as unknown as AuthPolicyAction[] }),
    ).toThrow('Default auth policy re-auth actions must be non-blank strings.')
    expect(() =>
      createDefaultAuthPolicy({ reAuthMaxAgeSeconds: Number.POSITIVE_INFINITY }),
    ).toThrow('Default auth policy re-auth max age must be a non-negative number.')
    expect(() =>
      defaultPolicy.requiresReAuth(
        null as unknown as Parameters<typeof defaultPolicy.requiresReAuth>[0],
      ),
    ).toThrow('Default auth policy re-auth context is required.')
    expect(() =>
      defaultPolicy.requiresReAuth({
        action: AuthPolicyAction.MergeAccounts,
        userId: asUserId('user-1'),
        now: new Date('invalid'),
      }),
    ).toThrow('Default auth policy re-auth time is invalid.')
    expect(() =>
      defaultPolicy.requiresReAuth({
        action: AuthPolicyAction.MergeAccounts,
        userId: asUserId('user-1'),
        now,
        reAuthenticatedAt: new Date('invalid'),
      }),
    ).toThrow('Default auth policy re-auth timestamp is invalid.')

    const error = new UniAuthError(UniAuthErrorCode.InvalidInput, 'Invalid.', { field: 'email' })

    expect(error.details).toEqual({ field: 'email' })
    expect(error.name).toBe('UniAuthError')
    expect(isUniAuthError(error)).toBe(true)
    expect(isUniAuthError(new Error('nope'))).toBe(false)
    expect(invalidInput().message).toBe('Invalid auth input.')
    expect(invalidCredentials().code).toBe(UniAuthErrorCode.InvalidCredentials)
  })
})
