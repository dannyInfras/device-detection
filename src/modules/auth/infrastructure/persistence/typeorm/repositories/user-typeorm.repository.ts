import { Injectable } from "@nestjs/common"
import { Repository } from "typeorm"
import { InjectRepository } from "@nestjs/typeorm"
import { UserOrmEntity } from "../entities/user.orm-entity"
import { User } from "../../../../domain/entities/user.entity"
import { UserRepository } from "../../../../domain/repositories/user.repository"

@Injectable()
export class UserTypeOrmRepository implements UserRepository {
  constructor(
    @InjectRepository(UserOrmEntity)
    private repository: Repository<UserOrmEntity>
  ) {}

  async findById(id: string): Promise<User | null> {
    const ormEntity = await this.repository.findOne({
      where: { id },
    })
    return this.mapToDomain(ormEntity)
  }

  async findByEmail(email: string): Promise<User | null> {
    const ormEntity = await this.repository.findOne({
      where: { email },
    })
    return this.mapToDomain(ormEntity)
  }

  async save(user: User): Promise<void> {
    const ormEntity = new UserOrmEntity()
    ormEntity.id = user.getId()
    ormEntity.email = user.getEmail()
    ormEntity.passwordHash = user.getPasswordHash()
    ormEntity.fullName = user.getFullName()
    ormEntity.roles = user.getRoles()
    ormEntity.createdAt = user.getCreatedAt()
    ormEntity.updatedAt = user.getUpdatedAt()

    await this.repository.save(ormEntity)
  }

  private mapToDomain(ormEntity: UserOrmEntity | null): User | null {
    if (!ormEntity) return null
    return new User({
      id: ormEntity.id,
      email: ormEntity.email,
      passwordHash: ormEntity.passwordHash,
      fullName: ormEntity.fullName,
      roles: ormEntity.roles,
    })
  }
} 