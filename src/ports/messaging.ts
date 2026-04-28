export interface EmailSender {
  sendEmail(input: {
    readonly to: string
    readonly subject: string
    readonly text: string
    readonly metadata?: Record<string, unknown>
  }): Promise<void>
}

export interface SmsSender {
  sendSms(input: {
    readonly to: string
    readonly text: string
    readonly metadata?: Record<string, unknown>
  }): Promise<void>
}
