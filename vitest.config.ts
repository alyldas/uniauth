import { defineConfig } from 'vitest/config'
import packageJson from './package.json'

const attributionDefines = {
  __UNIAUTH_PACKAGE_AUTHOR_EMAIL__: JSON.stringify(packageJson.author.email),
  __UNIAUTH_PACKAGE_AUTHOR_NAME__: JSON.stringify(packageJson.author.name),
  __UNIAUTH_PACKAGE_LICENSE__: JSON.stringify(packageJson.license),
  __UNIAUTH_PACKAGE_NAME__: JSON.stringify(packageJson.name),
  __UNIAUTH_PACKAGE_REPOSITORY_URL__: JSON.stringify(packageJson.repository.url),
}

export default defineConfig({
  define: attributionDefines,
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
