import { fileURLToPath } from 'node:url'
import { AuthPolicyAction, OtpChannel, addSeconds, createDefaultAuthPolicy } from '@alyldas/uniauth'
import { createInMemoryAuthKit } from '@alyldas/uniauth/testing'

const now = new Date('2026-01-01T00:00:00.000Z')

export async function runCurrentAccountContactChangeExample(): Promise<void> {
  const { service, emailSender, smsSender } = createInMemoryAuthKit({
    policy: createDefaultAuthPolicy({
      requireReAuthFor: [AuthPolicyAction.UpdateContact],
    }),
    verificationResendCooldownSeconds: 0,
  })
  const signedIn = await service.signIn({
    assertion: {
      provider: 'email',
      providerUserId: 'alice@example.com',
      email: 'alice@example.com',
      emailVerified: true,
      displayName: 'Alice Example',
    },
    now,
  })

  const emailChange = await service.startCurrentAccountContactChange({
    sessionToken: signedIn.sessionToken,
    channel: OtpChannel.Email,
    target: 'alice.new@example.com',
    secret: '123456',
    reAuthenticatedAt: now,
    now: addSeconds(now, 10),
    metadata: { route: 'account-contact-email-start' },
  })
  const emailDelivery = emailSender.listMessages().at(-1)

  if (!emailDelivery) {
    throw new Error('Expected the application-owned email sender to capture one message.')
  }

  const updated = await service.finishCurrentAccountContactChange({
    sessionToken: signedIn.sessionToken,
    verificationId: emailChange.verificationId,
    secret: '123456',
    now: addSeconds(now, 20),
    metadata: { route: 'account-contact-email-finish' },
  })
  const phoneChange = await service.startCurrentAccountContactChange({
    sessionToken: signedIn.sessionToken,
    channel: OtpChannel.Phone,
    target: '+1 (555) 000-0100',
    secret: '654321',
    reAuthenticatedAt: addSeconds(now, 20),
    now: addSeconds(now, 30),
    metadata: { route: 'account-contact-phone-start' },
  })
  const resentPhoneChange = await service.resendCurrentAccountContactChange({
    sessionToken: signedIn.sessionToken,
    verificationId: phoneChange.verificationId,
    secret: '777777',
    now: addSeconds(now, 40),
    metadata: { route: 'account-contact-phone-resend' },
  })
  const cancelledPhoneChange = await service.cancelCurrentAccountContactChange({
    sessionToken: signedIn.sessionToken,
    verificationId: resentPhoneChange.verificationId,
    now: addSeconds(now, 50),
    metadata: { route: 'account-contact-phone-cancel' },
  })

  console.log({
    userId: updated.id,
    email: updated.email ?? null,
    phone: updated.phone ?? null,
    emailDelivery: {
      to: emailDelivery.to,
      subject: emailDelivery.subject,
    },
    phoneDeliveryCount: smsSender.listMessages().length,
    cancelledPhoneChange: {
      verificationId: cancelledPhoneChange.id,
      status: cancelledPhoneChange.status,
      expiresAt: cancelledPhoneChange.expiresAt.toISOString(),
    },
  })
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  await runCurrentAccountContactChangeExample()
}
