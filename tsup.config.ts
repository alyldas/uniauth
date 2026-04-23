import { defineConfig } from 'tsup'
import packageJson from './package.json'

const attributionDefines = {
  __UNIAUTH_PACKAGE_AUTHOR_EMAIL__: JSON.stringify(packageJson.author.email),
  __UNIAUTH_PACKAGE_AUTHOR_NAME__: JSON.stringify(packageJson.author.name),
  __UNIAUTH_PACKAGE_LICENSE__: JSON.stringify(packageJson.license),
  __UNIAUTH_PACKAGE_NAME__: JSON.stringify(packageJson.name),
  __UNIAUTH_PACKAGE_REPOSITORY_URL__: JSON.stringify(packageJson.repository.url),
}

// noinspection JSUnusedGlobalSymbols -- tsup consumes the default export at runtime.
export default defineConfig({
  clean: true,
  define: attributionDefines,
  entry: {
    index: 'src/index.ts',
    'postgres/index': 'src/postgres.ts',
    'testing/index': 'src/testing/index.ts',
  },
  format: ['esm'],
  sourcemap: false,
  splitting: false,
  target: 'es2022',
})
