import type { EmailSender } from '@alyldas/uniauth'

export interface DeliveredEmail {
  readonly to: string
  readonly subject: string
  readonly text: string
  readonly metadata?: Record<string, unknown>
}

export class ConsoleEmailSender implements EmailSender {
  private readonly messages: DeliveredEmail[] = []

  constructor(private readonly framework: string) {}

  async sendEmail(input: DeliveredEmail): Promise<void> {
    this.messages.push(input)
    console.log(
      JSON.stringify(
        {
          type: 'demo-email',
          framework: this.framework,
          to: input.to,
          subject: input.subject,
          text: input.text,
        },
        null,
        2,
      ),
    )
  }

  listMessages(): readonly DeliveredEmail[] {
    return [...this.messages]
  }
}
