import { defineConfig } from 'vitest/config'

export default defineConfig({
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
