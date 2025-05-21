import { Injectable, Logger, BadRequestException } from "@nestjs/common"
import type { VerificationTokenRepository } from "../../domain/repositories/verification-token.repository"
import type { EmailService } from "../../domain/services/email.service"
import { VerificationToken } from "../../domain/entities/verification-token.entity"
import type { ClientKafka } from "@nestjs/microservices"
import { VerificationInitiatedEvent } from "../../domain/events/verification-initiated.event"
import type { DeviceRepository } from "../../../device/domain/repositories/device.repository"

@Injectable()
export class VerifyDeviceUseCase {
  private readonly logger = new Logger(VerifyDeviceUseCase.name)

  constructor(
    private deviceRepository: DeviceRepository,
    private tokenRepository: VerificationTokenRepository,
    private emailService: EmailService,
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

    // Emit event for async email sending and audit logging
    this.kafkaClient.emit(
      "verification.initiated",
      new VerificationInitiatedEvent(input.deviceId, input.userEmail, token.getToken()),
    )
  }
}
