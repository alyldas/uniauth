import type { EmailSender, SmsSender } from '../../ports.js'

export interface InMemoryEmailMessage {
  readonly to: string
  readonly subject: string
  readonly text: string
  readonly metadata?: Record<string, unknown>
}

export class InMemoryEmailSender implements EmailSender {
  private readonly messages: InMemoryEmailMessage[] = []

  async sendEmail(input: InMemoryEmailMessage): Promise<void> {
    this.messages.push(input)
  }

  listMessages(): readonly InMemoryEmailMessage[] {
    return [...this.messages]
  }
}

export interface InMemorySmsMessage {
  readonly to: string
  readonly text: string
  readonly metadata?: Record<string, unknown>
}

export class InMemorySmsSender implements SmsSender {
  private readonly messages: InMemorySmsMessage[] = []

  async sendSms(input: InMemorySmsMessage): Promise<void> {
    this.messages.push(input)
  }

  listMessages(): readonly InMemorySmsMessage[] {
    return [...this.messages]
  }
}
