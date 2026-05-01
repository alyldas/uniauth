import type { AuthServiceRuntime } from './runtime.js'
import { getAccountSecuritySnapshot } from './account-security.js'
import { getAuditEvents } from './audit-events.js'
import {
  toAccountInspectionSnapshot,
  type AccountInspectionSnapshot,
  type GetAccountInspectionSnapshotInput,
} from '../domain/types.js'

export async function getAccountInspectionSnapshot(
  runtime: AuthServiceRuntime,
  input: GetAccountInspectionSnapshotInput,
): Promise<AccountInspectionSnapshot> {
  const account = await getAccountSecuritySnapshot(runtime, input.userId)
  const auditEvents = await getAuditEvents(runtime, {
    userId: account.user.id,
    ...(input.auditLimit !== undefined ? { limit: input.auditLimit } : {}),
  })

  return toAccountInspectionSnapshot({
    account,
    auditEvents,
  })
}
