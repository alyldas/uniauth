import { fileURLToPath } from 'node:url'
import { createDefaultAuthPolicy } from '../../src'
import { createInMemoryAuthKit } from '../../src/testing'

export async function runBasicExample(): Promise<void> {
  const { service } = createInMemoryAuthKit({
    policy: createDefaultAuthPolicy({ allowAutoLink: false }),
  })

  const result = await service.signIn({
    assertion: {
      provider: 'email-otp',
      providerUserId: 'alice@example.com',
      email: 'alice@example.com',
      emailVerified: true,
      displayName: 'Alice',
    },
  })

  console.log({
    userId: result.user.id,
    identityId: result.identity.id,
    sessionId: result.session.id,
  })
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  await runBasicExample()
}
