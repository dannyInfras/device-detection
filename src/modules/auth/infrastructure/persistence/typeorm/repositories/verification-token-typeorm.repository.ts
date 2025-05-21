import { Injectable } from "@nestjs/common"
import { Repository } from "typeorm"
import { VerificationTokenOrmEntity } from "../entities/verification-token.orm-entity"
import type { VerificationTokenRepository } from "../../../../domain/repositories/verification-token.repository"
import { VerificationToken } from "../../../../domain/entities/verification-token.entity"
import { InjectRepository } from "@nestjs/typeorm"

@Injectable()
export class VerificationTokenTypeOrmRepository implements VerificationTokenRepository {
  constructor(
    @InjectRepository(VerificationTokenOrmEntity)
    private repository: Repository<VerificationTokenOrmEntity>
  ) {}

  async findById(id: string): Promise<VerificationToken | null> {
    const ormEntity = await this.repository.findOne({
      where: { id },
    })
    return this.mapToDomain(ormEntity)
  }

  async findByToken(token: string): Promise<VerificationToken | null> {
    const ormEntity = await this.repository.findOne({
      where: { token },
    })
    return this.mapToDomain(ormEntity)
  }

  async save(token: VerificationToken): Promise<void> {
    const ormEntity = new VerificationTokenOrmEntity()
    ormEntity.id = token.getId()
    ormEntity.deviceId = token.getDeviceId()
    ormEntity.token = token.getToken()
    ormEntity.expiresAt = token.getExpiresAt()

    await this.repository.save(ormEntity)
  }

  async deleteById(id: string): Promise<void> {
    await this.repository.delete(id)
  }

  private mapToDomain(ormEntity: VerificationTokenOrmEntity | null): VerificationToken | null {
    if (!ormEntity) return null
    return new VerificationToken({
      id: ormEntity.id,
      deviceId: ormEntity.deviceId,
      token: ormEntity.token,
      expiresAt: ormEntity.expiresAt,
    })
  }
}
