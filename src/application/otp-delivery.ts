import type { AuthServiceRuntime } from './runtime.js'
import {
  EMAIL_OTP_PROVIDER_ID,
  OtpChannel,
  PHONE_OTP_PROVIDER_ID,
  type CreateVerificationResult,
  type OtpChannel as OtpChannelType,
} from '../domain/types.js'
import { invalidInput } from '../errors.js'
import { normalizeEmail, normalizePhone, normalizeTarget } from '../utils/normalization.js'

const DEFAULT_EMAIL_OTP_SUBJECT = 'Your sign-in code'
const DEFAULT_SMS_OTP_PREFIX = 'Your sign-in code is'

export type SupportedOtpChannel = typeof OtpChannel.Email | typeof OtpChannel.Phone

export interface OtpDelivery {
  readonly provider: string
  send(created: CreateVerificationResult): Promise<void>
}

export function normalizeOtpTarget(channel: OtpChannelType, target: string): string {
  const normalized =
    channel === OtpChannel.Email
      ? normalizeEmail(target)
      : channel === OtpChannel.Phone
        ? normalizePhone(target)
        : normalizeTarget(target)

  if (normalized) {
    return normalized
  }

  if (channel === OtpChannel.Email) {
    throw invalidInput('Email is required.')
  }

  if (channel === OtpChannel.Phone) {
    throw invalidInput('Phone is required.')
  }

  throw invalidInput('OTP target is required.')
}

export function getOtpDelivery(runtime: AuthServiceRuntime, channel: OtpChannelType): OtpDelivery {
  if (channel === OtpChannel.Email) {
    if (!runtime.emailSender) {
      throw invalidInput('Email sender is required for email OTP challenges.')
    }

    const { emailSender } = runtime

    return {
      provider: EMAIL_OTP_PROVIDER_ID,
      send: async (created) => {
        await emailSender.sendEmail({
          to: created.verification.target,
          subject: DEFAULT_EMAIL_OTP_SUBJECT,
          text: `Your sign-in code is ${created.secret}.`,
          metadata: {
            verificationId: created.verification.id,
            purpose: created.verification.purpose,
            delivery: OtpChannel.Email,
          },
        })
      },
    }
  }

  if (channel === OtpChannel.Phone) {
    if (!runtime.smsSender) {
      throw invalidInput('SMS sender is required for phone OTP challenges.')
    }

    const { smsSender } = runtime

    return {
      provider: PHONE_OTP_PROVIDER_ID,
      send: async (created) => {
        await smsSender.sendSms({
          to: created.verification.target,
          text: `${DEFAULT_SMS_OTP_PREFIX} ${created.secret}.`,
          metadata: {
            verificationId: created.verification.id,
            purpose: created.verification.purpose,
            delivery: OtpChannel.Phone,
          },
        })
      },
    }
  }

  throw invalidInput('OTP channel is not supported.')
}
