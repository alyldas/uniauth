import { describe, expect, it } from 'vitest'
import {
  UniAuthError,
  UniAuthErrorCode,
  addSeconds,
  asAuditEventId,
  asIdentityId,
  asSessionId,
  asUserId,
  asVerificationId,
  createDefaultAuthPolicy,
  createHmacSecretHasher,
  createRandomIdGenerator,
  createSequentialIdGenerator,
  generateOtpSecret,
  generateSecret,
  hashSecret,
  invalidInput,
  isUniAuthError,
  normalizeEmail,
  normalizePhone,
  normalizeTarget,
  systemClock,
  verifySecret,
} from '../src'
import { assertion, identity, now, user } from './helpers.js'

describe('public utility coverage', () => {
  it('covers helper utilities and branded id casts', async () => {
    const randomIds = createRandomIdGenerator()

    expect(randomIds.userId()).toMatch(/^usr_/)
    expect(randomIds.identityId()).toMatch(/^idn_/)
    expect(randomIds.verificationId()).toMatch(/^vrf_/)
    expect(randomIds.sessionId()).toMatch(/^ses_/)
    expect(randomIds.auditEventId()).toMatch(/^aud_/)

    const sequentialIds = createSequentialIdGenerator('unit')

    expect(sequentialIds.userId()).toBe('unit_usr_1')
    expect(sequentialIds.identityId()).toBe('unit_idn_2')
    expect(sequentialIds.verificationId()).toBe('unit_vrf_3')
    expect(sequentialIds.sessionId()).toBe('unit_ses_4')
    expect(sequentialIds.auditEventId()).toBe('unit_aud_5')

    expect(asUserId('usr')).toBe('usr')
    expect(asIdentityId('idn')).toBe('idn')
    expect(asVerificationId('vrf')).toBe('vrf')
    expect(asSessionId('ses')).toBe('ses')
    expect(asAuditEventId('aud')).toBe('aud')

    expect(normalizeEmail(' Alice@Example.COM ')).toBe('alice@example.com')
    expect(normalizePhone(' +1 (555) 123-4567 ')).toBe('+15551234567')
    expect(normalizeTarget(' Alice@Example.COM ')).toBe('alice@example.com')
    expect(normalizeTarget(' +1 (555) 123-4567 ')).toBe('+15551234567')

    const generatedSecret = generateSecret(8)
    const generatedOtpSecret = generateOtpSecret()
    const secretHash = hashSecret('secret')
    const hmacHasher = createHmacSecretHasher({ pepper: 'test-pepper' })
    const hmacHash = await hmacHasher.hash('123456')

    expect(generatedSecret).toBeTypeOf('string')
    expect(generatedOtpSecret).toMatch(/^\d{6}$/)
    expect(verifySecret('secret', secretHash)).toBe(true)
    expect(verifySecret('secret', 'plaintext')).toBe(false)
    expect(verifySecret('secret', 'sha256:short')).toBe(false)
    expect(verifySecret('wrong', secretHash)).toBe(false)
    expect(hmacHash).toMatch(/^hmac-sha256:/)
    expect(await hmacHasher.verify('123456', hmacHash)).toBe(true)
    expect(await hmacHasher.verify('000000', hmacHash)).toBe(false)
    expect(await hmacHasher.verify('123456', secretHash)).toBe(false)
    expect(() => createHmacSecretHasher({ pepper: '' })).toThrow(
      'Secret hasher pepper is required.',
    )
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

    const error = new UniAuthError(UniAuthErrorCode.InvalidInput, 'Invalid.', { field: 'email' })

    expect(error.details).toEqual({ field: 'email' })
    expect(error.name).toBe('UniAuthError')
    expect(isUniAuthError(error)).toBe(true)
    expect(isUniAuthError(new Error('nope'))).toBe(false)
    expect(invalidInput().message).toBe('Invalid auth input.')
  })
})
