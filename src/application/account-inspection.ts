import type { AuthServiceRuntime } from './runtime.js'
import { getAccountSecuritySnapshot } from './account-security.js'
import { getAuditEventPage } from './audit-events.js'
import {
  toAccountInspectionSnapshot,
  type AccountInspectionSnapshot,
  type GetAccountInspectionSnapshotInput,
} from '../domain/types.js'
import { invalidInput } from '../errors.js'

export async function getAccountInspectionSnapshot(
  runtime: AuthServiceRuntime,
  input: GetAccountInspectionSnapshotInput,
): Promise<AccountInspectionSnapshot> {
  if (!isAccountInspectionInput(input)) {
    throw invalidInput('Account inspection input is required.')
  }

  const account = await getAccountSecuritySnapshot(runtime, input.userId)
  const auditWindow = input.audit
  const auditLimit = auditWindow?.limit ?? input.auditLimit
  const auditPage = await getAuditEventPage(runtime, {
    userId: account.user.id,
    ...(auditWindow?.before ? { before: auditWindow.before } : {}),
    ...(auditWindow?.after ? { after: auditWindow.after } : {}),
    ...(auditLimit !== undefined ? { limit: auditLimit } : {}),
  })

  return toAccountInspectionSnapshot({
    account,
    auditEvents: auditPage.events,
    ...(auditPage.nextCursor ? { nextAuditCursor: auditPage.nextCursor } : {}),
  })
}

function isAccountInspectionInput(value: unknown): value is GetAccountInspectionSnapshotInput {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}
