import { Injectable, Logger, BadRequestException, Inject } from "@nestjs/common"
import type { VerificationTokenRepository } from "../../domain/repositories/verification-token.repository"
import type { EmailService } from "../../domain/services/email.service"
import { VerificationToken } from "../../domain/entities/verification-token.entity"
import { ClientKafka } from "@nestjs/microservices"
import { VerificationInitiatedEvent } from "../../domain/events/verification-initiated.event"
import type { DeviceRepository } from "../../../device/domain/repositories/device.repository"

@Injectable()
export class VerifyDeviceUseCase {
  private readonly logger = new Logger(VerifyDeviceUseCase.name)

  constructor(
    @Inject("DeviceRepository")
    private deviceRepository: DeviceRepository,
    @Inject("VerificationTokenRepository")
    private tokenRepository: VerificationTokenRepository,
    @Inject("EmailService")
    private emailService: EmailService,
    @Inject("KAFKA_CLIENT")
    private kafkaClient: ClientKafka,
  ) {}

  async execute(input: { deviceId: string; userEmail: string }): Promise<void> {
    const device = await this.deviceRepository.findById(input.deviceId)
    if (!device) {
      throw new BadRequestException("Device not found")
    }

    if (device.getIsVerified()) {
      this.logger.warn(`Device ${input.deviceId} already verified`)
      return
    }

    const token = new VerificationToken({
      deviceId: input.deviceId,
      expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000), // 24 hours
    })

    await this.tokenRepository.save(token)
    this.logger.log(`Verification token created for device ${input.deviceId}`)

    // Instead of emitting to Kafka, send email directly
    try {
      await this.emailService.sendVerificationEmail(input.userEmail, token.getToken(), input.deviceId)
      this.logger.log(`Sent verification email directly for device ${input.deviceId}`)
    } catch (error) {
      this.logger.error(`Failed to send email directly: ${error.message}`)
    }
    
    // Commented out Kafka emission for now
    // this.kafkaClient.emit(
    //   "verification.initiated",
    //   new VerificationInitiatedEvent(input.deviceId, input.userEmail, token.getToken()),
    // )
  }
}
