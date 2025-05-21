import { Injectable, BadRequestException, Logger, Inject } from "@nestjs/common"
import type { DeviceRepository } from "../../../device/domain/repositories/device.repository"
import type { VerificationTokenRepository } from "../../domain/repositories/verification-token.repository"
import type { CacheService } from "../../../../common/interfaces/cache.interface"

@Injectable()
export class ConfirmDeviceVerificationUseCase {
  private readonly logger = new Logger(ConfirmDeviceVerificationUseCase.name)

  constructor(
    @Inject("DeviceRepository")
    private deviceRepository: DeviceRepository,
    @Inject("VerificationTokenRepository")
    private tokenRepository: VerificationTokenRepository,
    @Inject("CacheService")
    private cacheService: CacheService,
  ) {}

  async execute(token: string): Promise<void> {
    const verificationToken = await this.tokenRepository.findByToken(token)
    if (!verificationToken || verificationToken.isExpired()) {
      throw new BadRequestException("Invalid or expired token")
    }

    const device = await this.deviceRepository.findById(verificationToken.getDeviceId())
    if (!device) {
      throw new BadRequestException("Device not found")
    }

    device.verify()
    await this.deviceRepository.save(device)
    await this.tokenRepository.deleteById(verificationToken.getId())
    this.logger.log(`Device ${device.getId()} verified`)

    // Invalidate cache
    const cacheKey = `device:${device.getFingerprint()}`
    await this.cacheService.del(cacheKey)
  }
}
