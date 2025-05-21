import { Module } from "@nestjs/common"
import { TypeOrmModule } from "@nestjs/typeorm"
import { DetectDeviceUseCase } from "./application/use-cases/detect-device.use-case"
import { DeviceTypeOrmRepository } from "./infrastructure/persistence/typeorm/repositories/device-typeorm.repository"
import { DeviceOrmEntity } from "./infrastructure/persistence/typeorm/entities/device.orm-entity"
import { RedisCacheService } from "../../common/services/redis-cache.service"
import { CryptoService } from "../../common/utils/crypto.utils"
import { ClientsModule, Transport } from "@nestjs/microservices"
import { ConfigService, ConfigModule } from "@nestjs/config"
import { Reflector } from "@nestjs/core"
import { getRepositoryToken } from "@nestjs/typeorm"

@Module({
  imports: [
    TypeOrmModule.forFeature([DeviceOrmEntity]),
    ConfigModule,
    ClientsModule.registerAsync([
      {
        name: "KAFKA_CLIENT",
        imports: [ConfigModule],
        useFactory: (configService: ConfigService) => ({
          transport: Transport.KAFKA,
          options: {
            client: {
              clientId: configService.get('app.kafka.clientId') || 'auth-service',
              brokers: configService.get('app.kafka.brokers') || ['localhost:9092'],
            },
            consumer: {
              groupId: configService.get('app.kafka.groupId') || 'device-group',
            },
          },
        }),
        inject: [ConfigService],
      },
    ]),
  ],
  providers: [
    {
      provide: CryptoService,
      useFactory: (configService) => {
        return new CryptoService(configService);
      },
      inject: [ConfigService],
    },
    {
      provide: DeviceTypeOrmRepository,
      useFactory: (deviceRepo, cryptoService) => {
        return new DeviceTypeOrmRepository(deviceRepo, cryptoService);
      },
      inject: [getRepositoryToken(DeviceOrmEntity), CryptoService],
    },
    {
      provide: RedisCacheService,
      useFactory: (configService) => {
        return new RedisCacheService(configService);
      },
      inject: [ConfigService],
    },
    {
      provide: "DeviceRepository",
      useExisting: DeviceTypeOrmRepository,
    },
    {
      provide: "CacheService",
      useExisting: RedisCacheService,
    },
    {
      provide: DetectDeviceUseCase,
      useFactory: (deviceRepository, cacheService, kafkaClient, cryptoService) => {
        return new DetectDeviceUseCase(
          deviceRepository,
          cacheService,
          kafkaClient,
          cryptoService
        );
      },
      inject: ["DeviceRepository", "CacheService", "KAFKA_CLIENT", CryptoService],
    },
  ],
  exports: [DetectDeviceUseCase, "DeviceRepository"],
})
export class DeviceModule {}