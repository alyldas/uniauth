import { fileURLToPath } from 'node:url'
import { createDefaultAuthPolicy } from '@alyldas/uniauth'
import { createInMemoryAuthKit } from '@alyldas/uniauth/testing'

export async function runLinkUnlinkExample(): Promise<void> {
  const { service } = createInMemoryAuthKit({
    policy: createDefaultAuthPolicy({ allowAutoLink: false }),
  })

  const primary = await service.signIn({
    assertion: {
      provider: 'email',
      providerUserId: 'alice@example.com',
      email: 'alice@example.com',
      emailVerified: true,
      displayName: 'Alice Example',
    },
  })
  const linked = await service.link({
    userId: primary.user.id,
    assertion: {
      provider: 'github',
      providerUserId: 'github-alice',
      email: 'alice@example.com',
      emailVerified: true,
    },
  })

  const beforeUnlink = await service.getUserIdentities(primary.user.id)
  await service.unlink({
    userId: primary.user.id,
    identityId: linked.identity.id,
  })
  const afterUnlink = await service.getUserIdentities(primary.user.id)

  console.log({
    userId: primary.user.id,
    linkedIdentityId: linked.identity.id,
    beforeProviders: beforeUnlink.map((identity) => identity.provider),
    afterProviders: afterUnlink.map((identity) => identity.provider),
  })
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  await runLinkUnlinkExample()
}
