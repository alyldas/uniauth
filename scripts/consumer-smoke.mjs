import { spawnSync } from 'node:child_process'
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs'
import { createRequire } from 'node:module'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const require = createRequire(import.meta.url)
const packageMetadata = require('../package.json')
const repoRoot = resolve(fileURLToPath(new URL('..', import.meta.url)))

function run(command, args, options = {}) {
  const result = spawnSync(command, args, {
    cwd: options.cwd ?? repoRoot,
    encoding: 'utf8',
    shell: process.platform === 'win32',
    stdio: options.capture ? 'pipe' : 'inherit',
  })

  if (result.status !== 0) {
    const suffix = options.cwd ? ` in ${options.cwd}` : ''
    throw new Error(`Command failed${suffix}: ${command} ${args.join(' ')}`)
  }

  return result.stdout ?? ''
}

function parseNpmPackJson(output) {
  const jsonStart = output.lastIndexOf('\n[')
  const jsonText = (jsonStart >= 0 ? output.slice(jsonStart + 1) : output).trim()

  return JSON.parse(jsonText)
}

const workspace = mkdtempSync(join(tmpdir(), 'uniauth-consumer-smoke-'))

try {
  const packOutput = run('npm', ['pack', '--pack-destination', workspace, '--json'], {
    capture: true,
  })
  const [packed] = parseNpmPackJson(packOutput)

  if (!packed?.filename) {
    throw new Error('npm pack did not return a tarball filename.')
  }

  const packageFile = join(workspace, packed.filename)
  const consumerDir = join(workspace, 'consumer')
  mkdirSync(consumerDir)
  writeFileSync(
    join(consumerDir, 'package.json'),
    `${JSON.stringify(
      {
        private: true,
        type: 'module',
        dependencies: {},
      },
      null,
      2,
    )}\n`,
  )
  writeFileSync(
    join(consumerDir, 'consumer-smoke.mjs'),
    `import {
  SessionStatus,
  UNIAUTH_ATTRIBUTION,
  createDefaultAuthPolicy,
} from '${packageMetadata.name}'
import { createInMemoryAuthKit } from '${packageMetadata.name}/testing'

if (UNIAUTH_ATTRIBUTION.packageName !== '${packageMetadata.name}') {
  throw new Error('Unexpected package attribution.')
}

const { service } = createInMemoryAuthKit({
  policy: createDefaultAuthPolicy({ allowAutoLink: false }),
})

const result = await service.signIn({
  assertion: {
    provider: 'consumer-smoke',
    providerUserId: 'alice',
    email: 'alice@example.com',
    emailVerified: true,
  },
})

if (result.session.status !== SessionStatus.Active) {
  throw new Error('Expected an active local session.')
}

if (!result.isNewUser || !result.isNewIdentity) {
  throw new Error('Expected a new consumer-smoke user and identity.')
}
`,
  )

  run('npm', ['install', '--no-audit', '--no-fund', packageFile], { cwd: consumerDir })
  run(process.execPath, ['consumer-smoke.mjs'], { cwd: consumerDir })
  console.log(`Consumer smoke passed for ${packageMetadata.name}@${packageMetadata.version}.`)
} finally {
  if (process.env.UNIAUTH_KEEP_CONSUMER_SMOKE === '1') {
    console.log(`Consumer smoke workspace kept at ${workspace}.`)
  } else {
    rmSync(workspace, { force: true, recursive: true })
  }
}
