import { Module } from "@nestjs/common"
import { TypeOrmModule } from "@nestjs/typeorm"
import { JwtModule } from "@nestjs/jwt"
import { ClientsModule, Transport } from "@nestjs/microservices"
import { ConfigModule, ConfigService } from "@nestjs/config"
import { AuthController } from "./presentation/controllers/auth.controller"
import { VerifyDeviceUseCase } from "./application/use-cases/verify-device.use-case"
import { ConfirmDeviceVerificationUseCase } from "./application/use-cases/confirm-device-verification.use-case"
import { VerificationTokenTypeOrmRepository } from "./infrastructure/persistence/typeorm/repositories/verification-token-typeorm.repository"
import { NodemailerEmailService } from "./infrastructure/services/email/nodemailer-email.service"
import { VerificationTokenOrmEntity } from "./infrastructure/persistence/typeorm/entities/verification-token.orm-entity"
import { EmailConsumer } from "./infrastructure/kafka/email.consumer"
import { RedisCacheService } from "../../common/services/redis-cache.service"
import { RolesGuard } from "../../common/guards/roles.guard"
import { DeviceModule } from "../device/device.module"

@Module({
  imports: [
    TypeOrmModule.forFeature([VerificationTokenOrmEntity]),
    JwtModule.registerAsync({
      imports: [ConfigModule],
      useFactory: (configService: ConfigService) => ({
        secret: configService.get("app.jwt.secret"),
        signOptions: { expiresIn: configService.get("app.jwt.expiresIn") },
      }),
      inject: [ConfigService],
    }),
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
              groupId: "auth-group",
            },
          },
        }),
        inject: [ConfigService],
      },
    ]),
    DeviceModule,
  ],
  controllers: [AuthController],
  providers: [
    VerifyDeviceUseCase,
    ConfirmDeviceVerificationUseCase,
    VerificationTokenTypeOrmRepository,
    NodemailerEmailService,
    EmailConsumer,
    RedisCacheService,
    RolesGuard,
    {
      provide: "VerificationTokenRepository",
      useClass: VerificationTokenTypeOrmRepository,
    },
    {
      provide: "EmailService",
      useClass: NodemailerEmailService,
    },
    {
      provide: "CacheService",
      useClass: RedisCacheService,
    },
  ],
  exports: [VerifyDeviceUseCase, ConfirmDeviceVerificationUseCase],
})
export class AuthModule {}
