import { spawnSync } from 'node:child_process'
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { createRequire } from 'node:module'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

const require = createRequire(import.meta.url)
const packageMetadata = require('../package.json')
const registryUrl = 'https://npm.pkg.github.com'
const packageSpec = `${packageMetadata.name}@${packageMetadata.version}`

function run(command, args, options = {}) {
  const result = spawnSync(command, args, {
    cwd: options.cwd,
    encoding: 'utf8',
    env: { ...process.env, ...options.env },
    shell: process.platform === 'win32',
    stdio: 'inherit',
  })

  if (result.status !== 0) {
    const suffix = options.cwd ? ` in ${options.cwd}` : ''
    throw new Error(`Command failed${suffix}: ${command} ${args.join(' ')}`)
  }
}

function resolveAuthToken() {
  if (process.env.NODE_AUTH_TOKEN) {
    return process.env.NODE_AUTH_TOKEN
  }

  if (process.env.GITHUB_TOKEN) {
    return process.env.GITHUB_TOKEN
  }

  const result = spawnSync('gh', ['auth', 'token'], {
    encoding: 'utf8',
    shell: process.platform === 'win32',
    stdio: ['ignore', 'pipe', 'ignore'],
  })

  const token = result.stdout.trim()

  if (result.status === 0 && token) {
    return token
  }

  throw new Error(
    'GitHub Packages registry smoke requires NODE_AUTH_TOKEN, GITHUB_TOKEN, or authenticated gh CLI.',
  )
}

const workspace = mkdtempSync(join(tmpdir(), 'uniauth-registry-smoke-'))
const token = resolveAuthToken()

writeFileSync(
  join(workspace, '.npmrc'),
  `@alyldas:registry=${registryUrl}\n//npm.pkg.github.com/:_authToken=\${NODE_AUTH_TOKEN}\n`,
)
writeFileSync(join(workspace, 'package.json'), '{"private":true,"type":"module"}\n')
writeFileSync(
  join(workspace, 'registry-smoke.mjs'),
  `import { EMAIL_OTP_PROVIDER_ID, SessionStatus, UNIAUTH_ATTRIBUTION } from '${packageMetadata.name}'
import { createInMemoryAuthKit } from '${packageMetadata.name}/testing'

const { service } = createInMemoryAuthKit()
const result = await service.signIn({
  assertion: {
    provider: 'registry-smoke',
    providerUserId: 'alice',
    email: 'alice@example.com',
    emailVerified: true,
  },
})

if (UNIAUTH_ATTRIBUTION.packageName !== '${packageMetadata.name}') {
  throw new Error('Unexpected package attribution.')
}

if (result.session.status !== SessionStatus.Active) {
  throw new Error('Expected an active local session.')
}

const challenge = await service.startEmailOtpSignIn({
  email: 'otp@example.com',
  secret: '123456',
})
const otpResult = await service.finishEmailOtpSignIn({
  verificationId: challenge.verificationId,
  secret: '123456',
})

if (otpResult.identity.provider !== EMAIL_OTP_PROVIDER_ID) {
  throw new Error('Expected the email OTP provider identity.')
}

if (otpResult.session.status !== SessionStatus.Active) {
  throw new Error('Expected an active email OTP session.')
}
`,
)

try {
  run('npm', ['install', packageSpec, '--no-audit', '--no-fund'], {
    cwd: workspace,
    env: {
      NODE_AUTH_TOKEN: token,
      NPM_CONFIG_USERCONFIG: join(workspace, '.npmrc'),
    },
  })
  run(process.execPath, ['registry-smoke.mjs'], { cwd: workspace })
  console.log(`GitHub Packages registry smoke passed for ${packageSpec}.`)
} finally {
  if (process.env.UNIAUTH_KEEP_REGISTRY_SMOKE === '1') {
    console.log(`Registry smoke workspace kept at ${workspace}.`)
  } else {
    rmSync(workspace, { force: true, recursive: true })
  }
}
