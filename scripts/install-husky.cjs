/* eslint-disable @typescript-eslint/no-require-imports */
const { spawnSync } = require('node:child_process')
const { accessSync, constants, existsSync } = require('node:fs')

const HUSKY_SKIP_ENV_FLAGS = {
  CI: 'true',
  HUSKY: '0',
  npm_config_ignore_scripts: 'true',
}

if (shouldSkipHuskyInstall()) {
  process.exit(0)
}

if (!existsSync('.git') || !existsSync('.git/config')) {
  process.exit(0)
}

try {
  accessSync('.git/config', constants.W_OK)
} catch {
  process.exit(0)
}

const result = spawnSync('npx', ['husky'], {
  shell: process.platform === 'win32',
  stdio: 'inherit',
})

process.exit(result.status ?? 1)

function shouldSkipHuskyInstall() {
  return Object.entries(HUSKY_SKIP_ENV_FLAGS).some(
    ([key, expectedValue]) => process.env[key] === expectedValue,
  )
}
