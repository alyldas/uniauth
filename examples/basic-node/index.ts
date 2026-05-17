import { fileURLToPath } from 'node:url'
import { OtpChannel, VerificationPurpose, createDefaultAuthPolicy } from '@alyldas/uniauth'
import { createInMemoryAuthKit } from '@alyldas/uniauth/testing'

export async function runBasicExample(): Promise<void> {
  const { service } = createInMemoryAuthKit({
    policy: createDefaultAuthPolicy({ allowAutoLink: false }),
  })

  const challenge = await service.public.otp.start({
    purpose: VerificationPurpose.SignIn,
    channel: OtpChannel.Email,
    target: 'alice@example.com',
    secret: '123456',
  })
  const result = await service.public.otp.signIn({
    verificationId: challenge.verificationId,
    secret: '123456',
    channel: OtpChannel.Email,
  })

  console.log({
    userId: result.user.id,
    identityId: result.identity.id,
    sessionRecordId: result.session.id,
  })
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  await runBasicExample()
}
