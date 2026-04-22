import { defineConfig } from 'tsup'

// noinspection JSUnusedGlobalSymbols -- tsup consumes the default export at runtime.
export default defineConfig({
  clean: true,
  entry: {
    index: 'src/index.ts',
    'testing/index': 'src/testing/index.ts',
  },
  format: ['esm', 'cjs'],
  sourcemap: true,
  target: 'es2022',
})
