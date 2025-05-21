import { Injectable, Logger, Inject } from "@nestjs/common"
import type { DeviceRepository } from "../../domain/repositories/device.repository"
import { Device } from "../../domain/entities/device.entity"
import type { CacheService } from "../../../../common/interfaces/cache.interface"
import { ClientKafka } from "@nestjs/microservices"
import { DeviceDetectedEvent } from "../../domain/events/device-detected.event"
import { CryptoService } from "../../../../common/utils/crypto.utils"

@Injectable()
export class DetectDeviceUseCase {
  private readonly logger = new Logger(DetectDeviceUseCase.name)

  constructor(
    @Inject("DeviceRepository")
    private deviceRepository: DeviceRepository,
    @Inject("CacheService")
    private cacheService: CacheService,
    @Inject("KAFKA_CLIENT")
    private kafkaClient: ClientKafka,
    private cryptoService: CryptoService,
  ) {}

  async execute(input: {
    userId: string
    fingerprint: string
    userAgent: string
    ipAddress: string
  }): Promise<Device> {
    const cacheKey = `device:${this.cryptoService.encrypt(input.fingerprint)}`
    let device = await this.cacheService.get<Device>(cacheKey)

    if (!device) {
      device = await this.deviceRepository.findByFingerprint(input.fingerprint)
      if (!device) {
        device = new Device({
          userId: input.userId,
          fingerprint: input.fingerprint,
          userAgent: input.userAgent,
          ipAddress: input.ipAddress,
        })
        await this.deviceRepository.save(device)
        this.logger.log(`New device detected: ${device.getId()}`)

        // Emit event for async processing (e.g., audit logging)
        this.kafkaClient.emit(
          "device.detected",
          new DeviceDetectedEvent(
            device.getId(),
            device.getUserId(),
            device.getFingerprint(),
            device.getUserAgent(),
            device.getIpAddress(),
          ),
        )
      } else {
        device.updateLastUsed()
        await this.deviceRepository.save(device)
      }
      await this.cacheService.set(cacheKey, device, 60 * 60) // 1 hour TTL
    }

    return device
  }
}
