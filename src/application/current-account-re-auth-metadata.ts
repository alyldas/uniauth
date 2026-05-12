import { optionalProp } from './optional.js'
import { OtpChannel, type SessionId, type UserId } from '../domain/types.js'
import type { SupportedOtpChannel } from './otp-delivery.js'

const CURRENT_ACCOUNT_OTP_RE_AUTH_METADATA_KEY = 'currentAccountOtpReAuth'

export interface CurrentAccountOtpReAuthMetadata {
  readonly userId: string
  readonly sessionId: string
  readonly channel: SupportedOtpChannel
}

export function buildCurrentAccountOtpReAuthMetadata(
  userId: UserId,
  sessionId: SessionId,
  channel: SupportedOtpChannel,
  requestMetadata: Record<string, unknown> | undefined,
): Record<string, unknown> {
  return {
    [CURRENT_ACCOUNT_OTP_RE_AUTH_METADATA_KEY]: {
      userId,
      sessionId,
      channel,
    },
    ...optionalProp('requestMetadata', requestMetadata),
  }
}

export function readCurrentAccountOtpReAuthMetadata(
  metadata: Record<string, unknown> | undefined,
): CurrentAccountOtpReAuthMetadata | undefined {
  const raw = metadata?.[CURRENT_ACCOUNT_OTP_RE_AUTH_METADATA_KEY]

  if (!raw || typeof raw !== 'object') {
    return undefined
  }

  const candidate = raw as Partial<CurrentAccountOtpReAuthMetadata>

  if (
    typeof candidate.userId !== 'string' ||
    typeof candidate.sessionId !== 'string' ||
    (candidate.channel !== OtpChannel.Email && candidate.channel !== OtpChannel.Phone)
  ) {
    return undefined
  }

  return {
    userId: candidate.userId,
    sessionId: candidate.sessionId,
    channel: candidate.channel,
  }
}
