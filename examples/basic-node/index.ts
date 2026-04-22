import { fileURLToPath } from 'node:url'
import { createDefaultAuthPolicy } from '../../src'
import { createInMemoryAuthKit } from '../../src/testing'

export async function runBasicExample(): Promise<void> {
  const { service } = createInMemoryAuthKit({
    policy: createDefaultAuthPolicy({ allowAutoLink: false }),
  })

  const challenge = await service.startEmailOtpSignIn({
    email: 'alice@example.com',
    secret: '123456',
  })
  const result = await service.finishEmailOtpSignIn({
    verificationId: challenge.verificationId,
    secret: '123456',
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
