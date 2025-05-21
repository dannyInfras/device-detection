import { Injectable, Logger, type OnModuleInit } from "@nestjs/common"
import { type Consumer, Kafka } from "kafkajs"
import type { EmailService } from "../../domain/services/email.service"
import type { ConfigService } from "@nestjs/config"
import type { VerificationInitiatedEvent } from "../../domain/events/verification-initiated.event"

@Injectable()
export class EmailConsumer implements OnModuleInit {
  private readonly logger = new Logger(EmailConsumer.name)
  private consumer: Consumer

  constructor(
    private emailService: EmailService,
    private configService: ConfigService,
  ) {
    const kafka = new Kafka({
      clientId: this.configService.get("app.kafka.clientId"),
      brokers: this.configService.get("app.kafka.brokers"),
    })
    this.consumer = kafka.consumer({ groupId: "email-group" })
  }

  async onModuleInit() {
    await this.consumer.connect()
    await this.consumer.subscribe({ topic: "verification.initiated", fromBeginning: false })

    await this.consumer.run({
      eachMessage: async ({ message }) => {
        const event = JSON.parse(message.value.toString()) as VerificationInitiatedEvent
        try {
          await this.emailService.sendVerificationEmail(event.userEmail, event.token, event.deviceId)
          this.logger.log(`Processed verification email for device ${event.deviceId}`)
        } catch (error) {
          this.logger.error(`Failed to send email: ${error.message}`)
        }
      },
    })
  }
}
