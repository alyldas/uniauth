/* eslint-disable @typescript-eslint/no-require-imports */
const { spawnSync } = require('node:child_process')
const { existsSync } = require('node:fs')

if (!existsSync('.git')) {
  process.exit(0)
}

const result = spawnSync('npx', ['husky'], {
  shell: process.platform === 'win32',
  stdio: 'inherit',
})

process.exit(result.status ?? 1)
