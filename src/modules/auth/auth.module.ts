import { Module } from "@nestjs/common"
import { TypeOrmModule } from "@nestjs/typeorm"
import { JwtModule, JwtService } from "@nestjs/jwt"
import { ClientsModule, Transport } from "@nestjs/microservices"
import { ConfigModule, ConfigService } from "@nestjs/config"
import { AuthController } from "./presentation/controllers/auth.controller"
import { VerifyDeviceUseCase } from "./application/use-cases/verify-device.use-case"
import { ConfirmDeviceVerificationUseCase } from "./application/use-cases/confirm-device-verification.use-case"
import { RegisterUseCase } from "./application/use-cases/register.use-case"
import { LoginUseCase } from "./application/use-cases/login.use-case"
import { VerificationTokenTypeOrmRepository } from "./infrastructure/persistence/typeorm/repositories/verification-token-typeorm.repository"
import { UserTypeOrmRepository } from "./infrastructure/persistence/typeorm/repositories/user-typeorm.repository"
import { NodemailerEmailService } from "./infrastructure/services/email/nodemailer-email.service"
import { VerificationTokenOrmEntity } from "./infrastructure/persistence/typeorm/entities/verification-token.orm-entity"
import { UserOrmEntity } from "./infrastructure/persistence/typeorm/entities/user.orm-entity"
import { EmailConsumer } from "./infrastructure/kafka/email.consumer"
import { RedisCacheService } from "../../common/services/redis-cache.service"
import { RolesGuard } from "../../common/guards/roles.guard"
import { DeviceModule } from "../device/device.module"
import { Reflector } from "@nestjs/core"

@Module({
  imports: [
    TypeOrmModule.forFeature([VerificationTokenOrmEntity, UserOrmEntity]),
    ConfigModule,
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
              clientId: "auth-service",
              brokers: ["localhost:9092"],
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
    {
      provide: VerifyDeviceUseCase,
      useFactory: (deviceRepo, tokenRepo, emailService, kafkaClient) => {
        return new VerifyDeviceUseCase(deviceRepo, tokenRepo, emailService, kafkaClient);
      },
      inject: ["DeviceRepository", "VerificationTokenRepository", "EmailService", "KAFKA_CLIENT"],
    },
    {
      provide: ConfirmDeviceVerificationUseCase,
      useFactory: (deviceRepo, tokenRepo, cacheService) => {
        return new ConfirmDeviceVerificationUseCase(deviceRepo, tokenRepo, cacheService);
      },
      inject: ["DeviceRepository", "VerificationTokenRepository", "CacheService"],
    },
    {
      provide: RegisterUseCase,
      useFactory: (userRepo) => {
        return new RegisterUseCase(userRepo);
      },
      inject: ["UserRepository"],
    },
    {
      provide: LoginUseCase,
      useFactory: (userRepo) => {
        return new LoginUseCase(userRepo);
      },
      inject: ["UserRepository"],
    },
    VerificationTokenTypeOrmRepository,
    UserTypeOrmRepository,
    {
      provide: NodemailerEmailService,
      useFactory: (configService) => {
        return new NodemailerEmailService(configService);
      },
      inject: [ConfigService],
    },
    {
      provide: EmailConsumer,
      useFactory: (emailService, configService) => {
        return new EmailConsumer(emailService, configService);
      },
      inject: ["EmailService", ConfigService],
    },
    {
      provide: RedisCacheService,
      useFactory: (configService) => {
        return new RedisCacheService(configService);
      },
      inject: [ConfigService],
    },
    {
      provide: RolesGuard,
      useFactory: (reflector, jwtService) => {
        return new RolesGuard(reflector, jwtService);
      },
      inject: [Reflector, JwtService],
    },
    {
      provide: "VerificationTokenRepository",
      useClass: VerificationTokenTypeOrmRepository,
    },
    {
      provide: "UserRepository",
      useClass: UserTypeOrmRepository,
    },
    {
      provide: "EmailService",
      useClass: NodemailerEmailService,
    },
    {
      provide: "CacheService",
      useExisting: RedisCacheService,
    },
  ],
  exports: [VerifyDeviceUseCase, ConfirmDeviceVerificationUseCase, RegisterUseCase, LoginUseCase],
})
export class AuthModule {}
