import { Module } from "@nestjs/common"
import { ConfigModule, ConfigService } from "@nestjs/config"
import { TypeOrmModule } from "@nestjs/typeorm"
import { JwtModule } from "@nestjs/jwt"
import { ClientsModule, Transport } from "@nestjs/microservices"
import { DeviceModule } from "./modules/device/device.module"
import { AuthModule } from "./modules/auth/auth.module"
import appConfig from "./config/app.config"
import { DeviceOrmEntity } from "./modules/device/infrastructure/persistence/typeorm/entities/device.orm-entity"
import { VerificationTokenOrmEntity } from "./modules/auth/infrastructure/persistence/typeorm/entities/verification-token.orm-entity"
import { UserOrmEntity } from "./modules/auth/infrastructure/persistence/typeorm/entities/user.orm-entity"

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      load: [appConfig],
    }),
    TypeOrmModule.forRootAsync({
      useFactory: (configService: ConfigService) => ({
        type: "postgres",
        host: configService.get("app.db.host"),
        port: configService.get("app.db.port"),
        username: configService.get("app.db.username"),
        password: configService.get("app.db.password"),
        database: configService.get("app.db.name"),
        entities: [DeviceOrmEntity, VerificationTokenOrmEntity, UserOrmEntity],
        synchronize: configService.get("app.env") !== "production",
        ssl: configService.get("app.env") === "production" ? { rejectUnauthorized: false } : false,
      }),
      inject: [ConfigService],
    }),
    JwtModule.registerAsync({
      useFactory: (configService: ConfigService) => ({
        secret: configService.get("app.jwt.secret"),
        signOptions: { expiresIn: configService.get("app.jwt.expiresIn") },
      }),
      inject: [ConfigService],
    }),
    ClientsModule.registerAsync([
      {
        name: "KAFKA_CLIENT",
        useFactory: (configService: ConfigService) => ({
          transport: Transport.KAFKA,
          options: {
            client: {
              clientId: configService.get('app.kafka.clientId') || 'auth-service',
              brokers: configService.get('app.kafka.brokers') || ['localhost:9092']
            },
            consumer: {
              groupId: configService.get('app.kafka.groupId') || 'auth-group',
            },
          },
        }),
        inject: [ConfigService],
      },
    ]),
    DeviceModule,
    AuthModule,
  ],
})
export class AppModule {}
