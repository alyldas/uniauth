import { fileURLToPath } from 'node:url'
import { createDefaultAuthPolicy } from '@alyldas/uniauth'
import { createInMemoryAuthKit } from '@alyldas/uniauth/testing'

export async function runLinkUnlinkExample(): Promise<void> {
  const { service } = createInMemoryAuthKit({
    policy: createDefaultAuthPolicy({ allowAutoLink: false }),
  })

  const primary = await service.public.provider.signIn({
    assertion: {
      provider: 'email',
      providerUserId: 'alice@example.com',
      email: 'alice@example.com',
      emailVerified: true,
      displayName: 'Alice Example',
    },
  })
  const linked = await service.account.identities.link({
    sessionToken: primary.sessionToken,
    assertion: {
      provider: 'github',
      providerUserId: 'github-alice',
      email: 'alice@example.com',
      emailVerified: true,
    },
  })

  const beforeUnlink = await service.account.security.snapshot({
    sessionToken: primary.sessionToken,
  })
  await service.account.identities.unlink({
    sessionToken: primary.sessionToken,
    identityId: linked.identity.id,
  })
  const afterUnlink = await service.account.security.snapshot({
    sessionToken: primary.sessionToken,
  })

  console.log({
    userId: primary.user.id,
    linkedIdentityId: linked.identity.id,
    beforeProviders: beforeUnlink.account.identities.map((identity) => identity.provider),
    afterProviders: afterUnlink.account.identities.map((identity) => identity.provider),
  })
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  await runLinkUnlinkExample()
}
