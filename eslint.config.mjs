import prettier from 'eslint-config-prettier'
import globals from 'globals'
import tseslint from 'typescript-eslint'

function restrictImports(files, patterns, message) {
  return {
    files,
    rules: {
      'no-restricted-imports': [
        'error',
        {
          patterns: patterns.map((group) => ({ group: [group], message })),
        },
      ],
    },
  }
}

const providerAdapterPatterns = [
  '**/messenger.js',
  '**/oauth-oidc.js',
  '**/providers/messenger.js',
  '**/providers/messenger/**',
  '**/providers/oauth-oidc.js',
  '**/providers/oauth-oidc/**',
]

export default [
  {
    ignores: ['dist', 'coverage', 'node_modules', 'package-lock.json'],
  },
  ...tseslint.configs.recommended,
  prettier,
  {
    files: ['**/*.ts'],
    languageOptions: {
      globals: globals.node,
      parserOptions: {
        projectService: true,
        tsconfigRootDir: import.meta.dirname,
      },
    },
    rules: {
      '@typescript-eslint/consistent-type-imports': ['error', { fixStyle: 'inline-type-imports' }],
      '@typescript-eslint/no-explicit-any': 'error',
    },
  },
  restrictImports(
    ['src/domain/**/*.ts', 'src/contracts/**/*.ts', 'src/ports/**/*.ts'],
    [
      '**/application/**',
      '**/bridges.js',
      '**/bridges/**',
      '**/postgres.js',
      '**/postgres/**',
      '**/testing.js',
      '**/testing/**',
      '**/utils/**',
      ...providerAdapterPatterns,
    ],
    'Domain and contract layers must stay implementation-free and import only domain or contract code.',
  ),
  restrictImports(
    ['src/application/**/*.ts'],
    [
      '**/bridges.js',
      '**/bridges/**',
      '**/postgres.js',
      '**/postgres/**',
      '**/testing.js',
      '**/testing/**',
      ...providerAdapterPatterns,
    ],
    'Application orchestration must not depend on provider adapters, bridges, persistence adapters, or testing modules.',
  ),
  restrictImports(
    ['src/bridges.ts', 'src/bridges/**/*.ts'],
    [
      '**/application/**',
      '**/postgres.js',
      '**/postgres/**',
      '**/testing.js',
      '**/testing/**',
      ...providerAdapterPatterns,
    ],
    'Bridge helpers must stay independent from application, persistence, provider adapter, and testing internals.',
  ),
  restrictImports(
    ['src/messenger.ts', 'src/providers/messenger.ts', 'src/providers/messenger/**/*.ts'],
    [
      '**/application/**',
      '**/bridges.js',
      '**/bridges/**',
      '**/postgres.js',
      '**/postgres/**',
      '**/testing.js',
      '**/testing/**',
      '**/oauth-oidc.js',
      '**/providers/oauth-oidc.js',
      '**/providers/oauth-oidc/**',
    ],
    'Messenger provider adapters must not depend on application, persistence, bridge, testing, or OAuth/OIDC adapter internals.',
  ),
  restrictImports(
    ['src/oauth-oidc.ts', 'src/providers/oauth-oidc.ts', 'src/providers/oauth-oidc/**/*.ts'],
    [
      '**/application/**',
      '**/bridges.js',
      '**/bridges/**',
      '**/postgres.js',
      '**/postgres/**',
      '**/testing.js',
      '**/testing/**',
      '**/messenger.js',
      '**/providers/messenger.js',
      '**/providers/messenger/**',
    ],
    'OAuth/OIDC provider adapters must not depend on application, persistence, bridge, testing, or messenger adapter internals.',
  ),
  restrictImports(
    ['src/postgres.ts', 'src/postgres/**/*.ts'],
    [
      '**/application/**',
      '**/bridges.js',
      '**/bridges/**',
      '**/testing.js',
      '**/testing/**',
      ...providerAdapterPatterns,
    ],
    'Postgres adapters must stay below the application layer and independent from providers, bridges, and testing internals.',
  ),
  restrictImports(
    ['src/testing/**/*.ts'],
    [
      '**/bridges.js',
      '**/bridges/**',
      '**/postgres.js',
      '**/postgres/**',
      ...providerAdapterPatterns,
    ],
    'Testing helpers should compose public or application-facing boundaries, not provider, bridge, or persistence adapter internals.',
  ),
  restrictImports(
    ['src/utils/**/*.ts'],
    [
      '**/application/**',
      '**/bridges.js',
      '**/bridges/**',
      '**/postgres.js',
      '**/postgres/**',
      '**/testing.js',
      '**/testing/**',
      ...providerAdapterPatterns,
    ],
    'Utility modules must stay reusable and must not depend on application, adapters, or testing layers.',
  ),
]
