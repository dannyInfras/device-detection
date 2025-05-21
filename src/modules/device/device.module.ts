import { Module } from "@nestjs/common"
import { TypeOrmModule } from "@nestjs/typeorm"
import { DetectDeviceUseCase } from "./application/use-cases/detect-device.use-case"
import { DeviceTypeOrmRepository } from "./infrastructure/persistence/typeorm/repositories/device-typeorm.repository"
import { DeviceOrmEntity } from "./infrastructure/persistence/typeorm/entities/device.orm-entity"
import { RedisCacheService } from "../../common/services/redis-cache.service"
import { CryptoService } from "../../common/utils/crypto.utils"
import { ClientsModule, Transport } from "@nestjs/microservices"
import { ConfigService, ConfigModule } from "@nestjs/config"

@Module({
  imports: [
    TypeOrmModule.forFeature([DeviceOrmEntity]),
    ClientsModule.registerAsync([
      {
        name: "KAFKA_CLIENT",
        imports: [ConfigModule],
        useFactory: (configService: ConfigService) => ({
          transport: Transport.KAFKA,
          options: {
            client: {
              clientId: configService.get("app.kafka.clientId"),
              brokers: configService.get("app.kafka.brokers"),
            },
            consumer: {
              groupId: "device-group",
            },
          },
        }),
        inject: [ConfigService],
      },
    ]),
  ],
  providers: [
    DetectDeviceUseCase,
    DeviceTypeOrmRepository,
    RedisCacheService,
    CryptoService,
    {
      provide: "DeviceRepository",
      useClass: DeviceTypeOrmRepository,
    },
    {
      provide: "CacheService",
      useClass: RedisCacheService,
    },
  ],
  exports: [DetectDeviceUseCase, "DeviceRepository"],
})
export class DeviceModule {}
