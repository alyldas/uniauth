import { defineConfig } from 'vitest/config'
import packageJson from './package.json'

const sourceAliases = [
  {
    find: '@alyldas/uniauth/bridges',
    replacement: new URL('./src/bridges.ts', import.meta.url).pathname,
  },
  {
    find: '@alyldas/uniauth/contracts',
    replacement: new URL('./src/contracts.ts', import.meta.url).pathname,
  },
  {
    find: '@alyldas/uniauth/providers/messenger',
    replacement: new URL('./src/providers/messenger.ts', import.meta.url).pathname,
  },
  {
    find: '@alyldas/uniauth/providers/oauth-oidc',
    replacement: new URL('./src/providers/oauth-oidc.ts', import.meta.url).pathname,
  },
  {
    find: '@alyldas/uniauth/testing',
    replacement: new URL('./src/testing/index.ts', import.meta.url).pathname,
  },
  {
    find: '@alyldas/uniauth/postgres',
    replacement: new URL('./src/postgres.ts', import.meta.url).pathname,
  },
  {
    find: '@alyldas/uniauth',
    replacement: new URL('./src/index.ts', import.meta.url).pathname,
  },
]

const attributionDefines = {
  __UNIAUTH_PACKAGE_AUTHOR_EMAIL__: JSON.stringify(packageJson.author.email),
  __UNIAUTH_PACKAGE_AUTHOR_NAME__: JSON.stringify(packageJson.author.name),
  __UNIAUTH_PACKAGE_LICENSE__: JSON.stringify(packageJson.license),
  __UNIAUTH_PACKAGE_NAME__: JSON.stringify(packageJson.name),
  __UNIAUTH_PACKAGE_REPOSITORY_URL__: JSON.stringify(packageJson.repository.url),
}

export default defineConfig({
  define: attributionDefines,
  resolve: {
    alias: sourceAliases,
  },
  test: {
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json', 'clover'],
      include: ['src/**/*.ts'],
      exclude: ['src/index.ts', 'src/testing/index.ts'],
      thresholds: {
        100: true,
        perFile: true,
      },
    },
  },
})
