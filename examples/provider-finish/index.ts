import { fileURLToPath } from 'node:url'
import { createDefaultAuthPolicy } from '@alyldas/uniauth'
import { StaticAuthProvider, createInMemoryAuthKit } from '@alyldas/uniauth/testing'

export async function runProviderFinishExample(): Promise<void> {
  const { providerRegistry, service } = createInMemoryAuthKit({
    policy: createDefaultAuthPolicy({ allowAutoLink: true }),
  })
  const provider = new StaticAuthProvider('oidc-demo', {
    providerUserId: 'oidc-demo-user',
    email: 'alice@example.com',
    emailVerified: true,
    displayName: 'Alice Example',
  })

  providerRegistry.register(provider)

  const result = await service.public.provider.signIn({
    provider: 'oidc-demo',
    finishInput: {
      code: 'demo-code',
      state: 'demo-state',
      metadata: { redirectUri: 'https://app.example.test/callback' },
    },
  })

  console.log({
    userId: result.user.id,
    identityId: result.identity.id,
    provider: result.identity.provider,
    sessionRecordId: result.session.id,
  })
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  await runProviderFinishExample()
}
