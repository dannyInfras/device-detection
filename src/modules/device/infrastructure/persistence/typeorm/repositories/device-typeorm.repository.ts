import { Injectable, Inject } from "@nestjs/common"
import { Repository } from "typeorm"
import { DeviceOrmEntity } from "../entities/device.orm-entity"
import type { DeviceRepository } from "../../../../domain/repositories/device.repository"
import { Device } from "../../../../domain/entities/device.entity"
import type { CryptoService } from "../../../../../../common/utils/crypto.utils"
import { InjectRepository } from "@nestjs/typeorm"

@Injectable()
export class DeviceTypeOrmRepository implements DeviceRepository {
  constructor(
    @InjectRepository(DeviceOrmEntity)
    private repository: Repository<DeviceOrmEntity>,
    private cryptoService: CryptoService
  ) {}

  async findById(id: string): Promise<Device | null> {
    const ormEntity = await this.repository.findOne({
      where: { id },
      select: ["id", "userId", "fingerprint", "userAgent", "ipAddress", "isVerified", "createdAt", "lastUsedAt"],
    })
    return this.mapToDomain(ormEntity)
  }

  async findByFingerprint(fingerprint: string): Promise<Device | null> {
    const encryptedFingerprint = this.cryptoService.encrypt(fingerprint)
    const ormEntity = await this.repository.findOne({
      where: { fingerprint: encryptedFingerprint },
      select: ["id", "userId", "fingerprint", "userAgent", "ipAddress", "isVerified", "createdAt", "lastUsedAt"],
    })
    return this.mapToDomain(ormEntity)
  }

  async save(device: Device): Promise<void> {
    const ormEntity = new DeviceOrmEntity()
    ormEntity.id = device.getId()
    ormEntity.userId = device.getUserId()
    ormEntity.fingerprint = this.cryptoService.encrypt(device.getFingerprint())
    ormEntity.userAgent = device.getUserAgent()
    ormEntity.ipAddress = device.getIpAddress()
    ormEntity.isVerified = device.getIsVerified()
    ormEntity.createdAt = device.getCreatedAt()
    ormEntity.lastUsedAt = device.getLastUsedAt()

    await this.repository.upsert(ormEntity, ["id"])
  }

  private mapToDomain(ormEntity: DeviceOrmEntity | null): Device | null {
    if (!ormEntity) return null
    return new Device({
      id: ormEntity.id,
      userId: ormEntity.userId,
      fingerprint: this.cryptoService.decrypt(ormEntity.fingerprint),
      userAgent: ormEntity.userAgent,
      ipAddress: ormEntity.ipAddress,
    })
  }
}
