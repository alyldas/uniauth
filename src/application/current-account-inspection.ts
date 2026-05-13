import { getAccountSecuritySnapshotForUser } from './account-security.js'
import { getAuditEventPage } from './audit-events.js'
import type { AuthServiceRuntime } from './runtime.js'
import { resolveSessionContext } from './session-context.js'
import type {
  AuditEventPage,
  CurrentAccountClosureExportSnapshot,
  CurrentAccountInspectionSnapshot,
  GetCurrentAccountAuditEventPageInput,
  GetCurrentAccountClosureExportSnapshotInput,
  GetCurrentAccountInspectionSnapshotInput,
} from '../domain/types.js'
import { toCurrentAccountInspectionSnapshot } from '../domain/types.js'
import { invalidInput } from '../errors.js'

export async function getCurrentAccountInspectionSnapshot(
  runtime: AuthServiceRuntime,
  input: GetCurrentAccountInspectionSnapshotInput,
): Promise<CurrentAccountInspectionSnapshot> {
  assertCurrentAccountInspectionInput(input)

  const { session, user } = await resolveSessionContext(runtime, input)
  const account = await getAccountSecuritySnapshotForUser(runtime, user)
  const auditWindow = input.audit
  const auditLimit = auditWindow?.limit ?? input.auditLimit
  const auditPage = await getAuditEventPage(runtime, {
    userId: user.id,
    ...(auditWindow?.type ? { type: auditWindow.type } : {}),
    ...(auditWindow?.identityId ? { identityId: auditWindow.identityId } : {}),
    ...(auditWindow?.sessionId ? { sessionId: auditWindow.sessionId } : {}),
    ...(auditWindow?.before ? { before: auditWindow.before } : {}),
    ...(auditWindow?.after ? { after: auditWindow.after } : {}),
    ...(auditLimit !== undefined ? { limit: auditLimit } : {}),
  })

  return toCurrentAccountInspectionSnapshot({
    account,
    currentSessionId: session.id,
    auditEvents: auditPage.events,
    ...(auditPage.nextCursor ? { nextAuditCursor: auditPage.nextCursor } : {}),
  })
}

export async function getCurrentAccountClosureExportSnapshot(
  runtime: AuthServiceRuntime,
  input: GetCurrentAccountClosureExportSnapshotInput,
): Promise<CurrentAccountClosureExportSnapshot> {
  assertCurrentAccountInspectionInput(input)

  const generatedAt = input.now ?? runtime.clock.now()
  const inspection = await getCurrentAccountInspectionSnapshot(runtime, {
    ...input,
    now: generatedAt,
  })

  return {
    ...inspection,
    generatedAt,
  }
}

export async function getCurrentAccountAuditEventPage(
  runtime: AuthServiceRuntime,
  input: GetCurrentAccountAuditEventPageInput,
): Promise<AuditEventPage> {
  assertCurrentAccountInspectionInput(input)

  const { user } = await resolveSessionContext(runtime, input)

  return getAuditEventPage(runtime, {
    userId: user.id,
    ...(input.type ? { type: input.type } : {}),
    ...(input.identityId ? { identityId: input.identityId } : {}),
    ...(input.sessionId ? { sessionId: input.sessionId } : {}),
    ...(input.before ? { before: input.before } : {}),
    ...(input.after ? { after: input.after } : {}),
    ...(input.limit !== undefined ? { limit: input.limit } : {}),
  })
}

function assertCurrentAccountInspectionInput(
  input: unknown,
): asserts input is
  | GetCurrentAccountInspectionSnapshotInput
  | GetCurrentAccountClosureExportSnapshotInput
  | GetCurrentAccountAuditEventPageInput {
  if (typeof input !== 'object' || input === null || Array.isArray(input)) {
    throw invalidInput('Current-account inspection input is required.')
  }
}
