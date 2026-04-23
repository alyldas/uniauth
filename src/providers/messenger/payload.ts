import type { FinishInput } from '../../domain/types.js'
import { invalidInput } from '../../errors.js'
import { invalidSignedWebAppInitData, isRecord, readString } from './support.js'

export function readWebAppInitData(input: FinishInput): string {
  if (typeof input.payload === 'string') {
    return input.payload
  }

  if (isRecord(input.payload)) {
    const initData = readString(input.payload.initData)

    if (initData) {
      return initData
    }

    const url = readString(input.payload.url)

    if (url) {
      return url
    }
  }

  throw invalidInput('Signed WebApp init data payload is required.')
}

export function normalizeMaxWebAppInitData(value: string): string {
  return isMaxWebAppDataContainer(value) ? extractMaxWebAppInitData(value) : value
}

function isMaxWebAppDataContainer(value: string): boolean {
  return value.includes('#') || value.startsWith('WebAppData=') || value.includes('&WebAppData=')
}

function extractMaxWebAppInitData(value: string): string {
  const params = new URLSearchParams(extractUrlFragment(value))
  const seen = new Set<string>()

  for (const key of params.keys()) {
    if (seen.has(key)) {
      throw invalidSignedWebAppInitData()
    }

    seen.add(key)
  }

  const appData = params.get('WebAppData')

  if (!appData) {
    throw invalidSignedWebAppInitData()
  }

  return appData
}

function extractUrlFragment(value: string): string {
  const hashIndex = value.indexOf('#')

  if (hashIndex === -1) {
    return value
  }

  return value.slice(hashIndex + 1)
}
