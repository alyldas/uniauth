/* eslint-disable @typescript-eslint/no-require-imports */
const { existsSync, readdirSync, readFileSync } = require('node:fs')
const { dirname, join, resolve } = require('node:path')

const MARKDOWN_LINK_PATTERN = /(?<!!)\[[^\]]+\]\(([^)]+)\)/g
const MARKDOWN_DIRECTORIES = ['docs', '.github']

const markdownFiles = [
  ...readdirSync('.').filter((file) => file.endsWith('.md')),
  ...MARKDOWN_DIRECTORIES.flatMap((directory) => listMarkdownFiles(directory)),
]
const brokenLinks = []

for (const file of markdownFiles) {
  const contents = readFileSync(file, 'utf8')

  for (const match of contents.matchAll(MARKDOWN_LINK_PATTERN)) {
    const rawTarget = match[1]?.trim()
    const target = readLocalTarget(rawTarget)

    if (!target) {
      continue
    }

    const [pathTarget] = target.split('#')

    if (!pathTarget) {
      continue
    }

    const resolvedTarget = resolve(dirname(file), decodeURIComponent(pathTarget))

    if (!existsSync(resolvedTarget)) {
      brokenLinks.push(`${file}: ${target}`)
    }
  }
}

if (brokenLinks.length > 0) {
  console.error('Broken local Markdown links found:')

  for (const brokenLink of brokenLinks) {
    console.error(`- ${brokenLink}`)
  }

  process.exit(1)
}

function listMarkdownFiles(directory) {
  if (!existsSync(directory)) {
    return []
  }

  return readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const path = join(directory, entry.name)

    if (entry.isDirectory()) {
      return listMarkdownFiles(path)
    }

    return entry.isFile() && path.endsWith('.md') ? [path] : []
  })
}

function readLocalTarget(rawTarget) {
  if (!rawTarget) {
    return undefined
  }

  const target = rawTarget.replace(/^<|>$/g, '').split(/\s+/u)[0]

  if (!target || target.startsWith('#') || /^[a-z][a-z+.-]*:/iu.test(target)) {
    return undefined
  }

  return target
}
