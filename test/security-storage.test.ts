import { describe, expect, it } from 'vitest'
import {
  UniAuthErrorCode,
  VerificationPurpose,
  VerificationStatus,
  addSeconds,
  type AuthService,
  type Credential,
  type Session,
  type UserId,
  type Verification,
  type VerificationId,
} from '../src'
import { createInMemoryAuthKit } from '../src/testing'
import { assertion, now } from './helpers.js'
import { createPostgresTestKit } from './postgres/support.js'

interface StorageKit {
  readonly service: AuthService
  readonly store: {
    readonly credentialRepo: {
      findPasswordByUserId(userId: UserId): Promise<Credential | undefined>
    }
    readonly verificationRepo: {
      findById(verificationId: VerificationId): Promise<Verification | undefined>
      findByIdForUpdate(verificationId: VerificationId): Promise<Verification | undefined>
    }
    readonly sessionRepo: {
      findByTokenHash(tokenHash: string): Promise<Session | undefined>
      listByUserId(userId: UserId): Promise<readonly Session[]>
    }
  }
}

interface StorageKitFactory {
  readonly label: string
  readonly create: () => Promise<StorageKit>
}

const storageKits: readonly StorageKitFactory[] = [
  {
    label: 'in-memory',
    async create() {
      return createInMemoryAuthKit()
    },
  },
  {
    label: 'Postgres',
    async create() {
      return createPostgresTestKit()
    },
  },
]

async function createEmailUser(service: AuthService, email: string) {
  return service.signIn({
    assertion: assertion({
      provider: 'email',
      providerUserId: email,
      email,
      emailVerified: true,
    }),
    now,
  })
}

describe('security storage regressions', () => {
  for (const { label, create } of storageKits) {
    it(`${label} stores only password hashes across set and change`, async () => {
      const { service, store } = await create()
      const email = `${label.toLowerCase()}-password@example.com`
      const signedIn = await createEmailUser(service, email)

      const created = await service.setPassword({
        userId: signedIn.user.id,
        email,
        password: 'first-password',
        now,
      })
      const storedAfterSet = await store.credentialRepo.findPasswordByUserId(signedIn.user.id)

      expect(storedAfterSet?.passwordHash).toBe(created.passwordHash)
      expect(storedAfterSet?.passwordHash).not.toBe('first-password')

      const changed = await service.changePassword({
        userId: signedIn.user.id,
        currentPassword: 'first-password',
        newPassword: 'second-password',
        now: addSeconds(now, 10),
      })
      const storedAfterChange = await store.credentialRepo.findPasswordByUserId(signedIn.user.id)

      expect(storedAfterChange?.passwordHash).toBe(changed.passwordHash)
      expect(storedAfterChange?.passwordHash).not.toBe('second-password')
      expect(storedAfterChange?.passwordHash).not.toBe(created.passwordHash)
    })

    it(`${label} stores only hashed verification secrets through create and consume`, async () => {
      const { service, store } = await create()
      const created = await service.createVerification({
        purpose: VerificationPurpose.Link,
        target: `${label.toLowerCase()}-opaque-target`,
        secret: '123456',
        now,
      })
      const storedPending = await store.verificationRepo.findById(created.verification.id)

      expect(storedPending?.secretHash).toBe(created.verification.secretHash)
      expect(storedPending?.secretHash).not.toBe('123456')
      expect(storedPending).toMatchObject({
        status: VerificationStatus.Pending,
      })

      await service.consumeVerification({
        verificationId: created.verification.id,
        secret: '123456',
        now: addSeconds(now, 10),
      })
      const storedConsumed = await store.verificationRepo.findById(created.verification.id)

      expect(storedConsumed?.secretHash).toBe(created.verification.secretHash)
      expect(storedConsumed).toMatchObject({
        status: VerificationStatus.Consumed,
      })
    })

    it(`${label} stores only session token hashes while resolving raw session tokens`, async () => {
      const { service, store } = await create()
      const email = `${label.toLowerCase()}-session@example.com`
      const signedIn = await createEmailUser(service, email)
      const secondSession = await service.createSession({
        userId: signedIn.user.id,
        now: addSeconds(now, 5),
      })
      const storedSessions = await store.sessionRepo.listByUserId(signedIn.user.id)

      expect(signedIn.session.tokenHash).not.toBe(signedIn.sessionToken)
      expect(secondSession.session.tokenHash).not.toBe(secondSession.sessionToken)
      expect(storedSessions).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            id: signedIn.session.id,
            tokenHash: signedIn.session.tokenHash,
          }),
          expect.objectContaining({
            id: secondSession.session.id,
            tokenHash: secondSession.session.tokenHash,
          }),
        ]),
      )

      await expect(
        service.resolveSession({
          sessionToken: signedIn.sessionToken,
          now,
        }),
      ).resolves.toMatchObject({
        id: signedIn.session.id,
      })
      await expect(
        service.resolveSession({
          sessionToken: secondSession.sessionToken,
          now: addSeconds(now, 5),
        }),
      ).resolves.toMatchObject({
        id: secondSession.session.id,
      })
      await expect(
        service.resolveSession({
          sessionToken: 123,
          now,
        } as unknown as Parameters<typeof service.resolveSession>[0]),
      ).rejects.toMatchObject({
        code: UniAuthErrorCode.InvalidInput,
        message: 'Session token is required.',
      })
      await expect(
        service.resolveSession({
          sessionToken: signedIn.sessionToken,
          now: 'not-a-date',
        } as unknown as Parameters<typeof service.resolveSession>[0]),
      ).rejects.toMatchObject({
        code: UniAuthErrorCode.InvalidInput,
        message: 'Session resolution time is invalid.',
      })
      await expect(
        service.createSession({
          userId: signedIn.user.id,
          now: 'not-a-date',
        } as unknown as Parameters<typeof service.createSession>[0]),
      ).rejects.toMatchObject({
        code: UniAuthErrorCode.InvalidInput,
        message: 'Session creation time is invalid.',
      })

      expect(await store.sessionRepo.findByTokenHash(signedIn.sessionToken)).toBeUndefined()
      expect(await store.sessionRepo.findByTokenHash(secondSession.sessionToken)).toBeUndefined()
      expect(await store.sessionRepo.findByTokenHash(signedIn.session.tokenHash)).toMatchObject({
        id: signedIn.session.id,
      })
      expect(
        await store.sessionRepo.findByTokenHash(secondSession.session.tokenHash),
      ).toMatchObject({
        id: secondSession.session.id,
      })
    })
  }
})
