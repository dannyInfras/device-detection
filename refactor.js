import fs from 'fs';
import path from 'path';

// Define the project structure
const projectStructure = {
  'src': {
    'common': {
      'decorators': {
        'roles.decorator.ts': `import { SetMetadata } from '@nestjs/common';

export const ROLES_KEY = 'roles';
export const Roles = (...roles: string[]) => SetMetadata(ROLES_KEY, roles);`
      },
      'guards': {
        'roles.guard.ts': `import { Injectable, CanActivate, ExecutionContext } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { ROLES_KEY } from '../decorators/roles.decorator';
import { JwtService } from '@nestjs/jwt';

@Injectable()
export class RolesGuard implements CanActivate {
  constructor(private reflector: Reflector, private jwtService: JwtService) {}

  canActivate(context: ExecutionContext): boolean {
    const requiredRoles = this.reflector.getAllAndOverride<string[]>(ROLES_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);
    if (!requiredRoles) return true;

    const request = context.switchToHttp().getRequest();
    const token = request.headers.authorization?.replace('Bearer ', '');
    if (!token) return false;

    const payload = this.jwtService.verify(token);
    return requiredRoles.some((role) => payload.roles?.includes(role));
  }
}`
      },
      'interceptors': {
        'logging.interceptor.ts': `import { Injectable, NestInterceptor, ExecutionContext, CallHandler, Logger } from '@nestjs/common';
import { Observable } from 'rxjs';
import { tap } from 'rxjs/operators';

@Injectable()
export class LoggingInterceptor implements NestInterceptor {
  private logger = new Logger('HTTP');

  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    const request = context.switchToHttp().getRequest();
    const { method, url } = request;
    const start = Date.now();

    return next.handle().pipe(
      tap(() => {
        const duration = Date.now() - start;
        this.logger.log(\`\${method} \${url} - \${duration}ms\`);
      }),
    );
  }
}`
      },
      'interfaces': {
        'cache.interface.ts': `export interface CacheService {
  get<T>(key: string): Promise<T | null>;
  set<T>(key: string, value: T, ttl?: number): Promise<void>;
  del(key: string): Promise<void>;
}`
,
        'repository.interface.ts': `export interface Repository<T> {
  findById(id: string): Promise<T | null>;
  save(entity: T): Promise<void>;
}`
      },
      'services': {
        'redis-cache.service.ts': `import { Injectable, Logger } from '@nestjs/common';
import { CacheService } from '../interfaces/cache.interface';
import { Redis } from 'ioredis';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class RedisCacheService implements CacheService {
  private readonly logger = new Logger(RedisCacheService.name);
  private client: Redis;

  constructor(configService: ConfigService) {
    this.client = new Redis(configService.get('app.redis.url'));
    this.client.on('error', (err) => this.logger.error(\`Redis error: \${err.message}\`));
  }

  async get<T>(key: string): Promise<T | null> {
    const data = await this.client.get(key);
    return data ? JSON.parse(data) : null;
  }

  async set<T>(key: string, value: T, ttl?: number): Promise<void> {
    const stringValue = JSON.stringify(value);
    if (ttl) {
      await this.client.setex(key, ttl, stringValue);
    } else {
      await this.client.set(key, stringValue);
    }
  }

  async del(key: string): Promise<void> {
    await this.client.del(key);
  }
}`
      },
      'utils': {
        'crypto.utils.ts': `import { createCipheriv, createDecipheriv, randomBytes } from 'crypto';
import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class CryptoService {
  private algorithm = 'aes-256-cbc';
  private key: Buffer;

  constructor(configService: ConfigService) {
    this.key = Buffer.from(configService.get('app.encryption.key'), 'hex');
  }

  encrypt(text: string): string {
    const iv = randomBytes(16);
    const cipher = createCipheriv(this.algorithm, this.key, iv);
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return \`\${iv.toString('hex')}:\${encrypted}\`;
  }

  decrypt(encryptedText: string): string {
    const [ivHex, encrypted] = encryptedText.split(':');
    const iv = Buffer.from(ivHex, 'hex');
    const decipher = createDecipheriv(this.algorithm, this.key, iv);
    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
  }
}`
,
        'circuit-breaker.ts': `export class CircuitBreaker {
  private failureCount: number;
  private lastFailureTime: number | null;
  private readonly options: {
    failureThreshold: number;
    resetTimeout: number;
  };

  constructor(options: { failureThreshold: number; resetTimeout: number }) {
    this.failureCount = 0;
    this.lastFailureTime = null;
    this.options = options;
  }

  async execute<T>(fn: () => Promise<T>): Promise<T> {
    if (this.isOpen()) {
      throw new Error('Circuit breaker is open');
    }

    try {
      const result = await fn();
      this.reset();
      return result;
    } catch (error) {
      this.failureCount++;
      this.lastFailureTime = Date.now();
      throw error;
    }
  }

  private isOpen(): boolean {
    return this.failureCount >= this.options.failureThreshold &&
      (this.lastFailureTime === null || Date.now() - this.lastFailureTime < this.options.resetTimeout);
  }

  private reset(): void {
    this.failureCount = 0;
    this.lastFailureTime = null;
  }
}`
      }
    },
    'config': {
      'app.config.ts': `import { registerAs } from '@nestjs/config';
import { randomBytes } from 'crypto';

export default registerAs('app', () => ({
  env: process.env.NODE_ENV || 'development',
  port: parseInt(process.env.PORT, 10) || 3000,
  url: process.env.APP_URL || 'http://localhost:3000',
  jwt: {
    secret: process.env.JWT_SECRET || 'your-jwt-secret',
    expiresIn: '24h',
  },
  redis: {
    url: process.env.REDIS_URL || 'redis://localhost:6379',
  },
  kafka: {
    brokers: process.env.KAFKA_BROKERS?.split(',') || ['localhost:9092'],
    clientId: 'auth-service',
  },
  email: {
    provider: process.env.EMAIL_PROVIDER || 'nodemailer',
    host: process.env.EMAIL_HOST,
    port: parseInt(process.env.EMAIL_PORT, 10) || 587,
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
  encryption: {
    key: process.env.ENCRYPTION_KEY || Buffer.from(randomBytes(32)).toString('hex'),
  },
  rateLimit: {
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // 100 requests
  },
  db: {
    host: process.env.DB_HOST || 'localhost',
    port: parseInt(process.env.DB_PORT, 10) || 5432,
    username: process.env.DB_USERNAME || 'postgres',
    password: process.env.DB_PASSWORD || 'postgres',
    name: process.env.DB_NAME || 'auth_service',
  },
}));`
    },
    'modules': {
      'device': {
        'device.module.ts': `import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { DetectDeviceUseCase } from './application/use-cases/detect-device.use-case';
import { DeviceTypeOrmRepository } from './infrastructure/persistence/typeorm/repositories/device-typeorm.repository';
import { DeviceOrmEntity } from './infrastructure/persistence/typeorm/entities/device.orm-entity';
import { RedisCacheService } from '../../common/services/redis-cache.service';
import { CryptoService } from '../../common/utils/crypto.utils';
import { ClientsModule, Transport } from '@nestjs/microservices';
import { ConfigService, ConfigModule } from '@nestjs/config';

@Module({
  imports: [
    TypeOrmModule.forFeature([DeviceOrmEntity]),
    ClientsModule.registerAsync([
      {
        name: 'KAFKA_CLIENT',
        imports: [ConfigModule],
        useFactory: (configService: ConfigService) => ({
          transport: Transport.KAFKA,
          options: {
            client: {
              clientId: configService.get('app.kafka.clientId'),
              brokers: configService.get('app.kafka.brokers'),
            },
            consumer: {
              groupId: 'device-group',
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
      provide: 'DeviceRepository',
      useClass: DeviceTypeOrmRepository,
    },
    {
      provide: 'CacheService',
      useClass: RedisCacheService,
    },
  ],
  exports: [DetectDeviceUseCase, 'DeviceRepository'],
})
export class DeviceModule {}`
,
        'domain': {
          'entities': {
            'device.entity.ts': `import { v4 as uuidv4 } from 'uuid';

/**
 * Domain entity representing a user device.
 */
export class Device {
  private id: string;
  private userId: string;
  private fingerprint: string; // Encrypted in storage
  private userAgent: string;
  private ipAddress: string;
  private isVerified: boolean;
  private createdAt: Date;
  private lastUsedAt: Date;

  constructor(props: {
    id?: string;
    userId: string;
    fingerprint: string;
    userAgent: string;
    ipAddress: string;
  }) {
    this.id = props.id ?? uuidv4();
    this.userId = props.userId;
    this.fingerprint = props.fingerprint;
    this.userAgent = props.userAgent;
    this.ipAddress = props.ipAddress;
    this.isVerified = false;
    this.createdAt = new Date();
    this.lastUsedAt = new Date();
  }

  verify(): void {
    this.isVerified = true;
    this.lastUsedAt = new Date();
  }

  updateLastUsed(): void {
    this.lastUsedAt = new Date();
  }

  getId(): string { return this.id; }
  getUserId(): string { return this.userId; }
  getFingerprint(): string { return this.fingerprint; }
  getIsVerified(): boolean { return this.isVerified; }
  getUserAgent(): string { return this.userAgent; }
  getIpAddress(): string { return this.ipAddress; }
  getCreatedAt(): Date { return this.createdAt; }
  getLastUsedAt(): Date { return this.lastUsedAt; }
}`
          },
          'repositories': {
            'device.repository.ts': `import { Device } from '../entities/device.entity';
import { Repository } from '../../../../common/interfaces/repository.interface';

export interface DeviceRepository extends Repository<Device> {
  findByFingerprint(fingerprint: string): Promise<Device | null>;
}`
          },
          'events': {
            'device-detected.event.ts': `export class DeviceDetectedEvent {
  constructor(
    public readonly deviceId: string,
    public readonly userId: string,
    public readonly fingerprint: string,
    public readonly userAgent: string,
    public readonly ipAddress: string,
  ) {}
}`
          }
        },
        'application': {
          'use-cases': {
            'detect-device.use-case.ts': `import { Injectable, Inject, Logger } from '@nestjs/common';
import { DeviceRepository } from '../../domain/repositories/device.repository';
import { Device } from '../../domain/entities/device.entity';
import { CacheService } from '../../../../common/interfaces/cache.interface';
import { ClientKafka } from '@nestjs/microservices';
import { DeviceDetectedEvent } from '../../domain/events/device-detected.event';
import { CryptoService } from '../../../../common/utils/crypto.utils';

@Injectable()
export class DetectDeviceUseCase {
  private readonly logger = new Logger(DetectDeviceUseCase.name);

  constructor(
    @Inject('DeviceRepository') private deviceRepository: DeviceRepository,
    @Inject('CacheService') private cacheService: CacheService,
    @Inject('KAFKA_CLIENT') private kafkaClient: ClientKafka,
    private cryptoService: CryptoService,
  ) {}

  async execute(input: {
    userId: string;
    fingerprint: string;
    userAgent: string;
    ipAddress: string;
  }): Promise<Device> {
    const cacheKey = \`device:\${this.cryptoService.encrypt(input.fingerprint)}\`;
    let device = await this.cacheService.get<Device>(cacheKey);

    if (!device) {
      device = await this.deviceRepository.findByFingerprint(input.fingerprint);
      if (!device) {
        device = new Device({
          userId: input.userId,
          fingerprint: input.fingerprint,
          userAgent: input.userAgent,
          ipAddress: input.ipAddress,
        });
        await this.deviceRepository.save(device);
        this.logger.log(\`New device detected: \${device.getId()}\`);

        // Emit event for async processing (e.g., audit logging)
        this.kafkaClient.emit('device.detected', new DeviceDetectedEvent(
          device.getId(),
          device.getUserId(),
          device.getFingerprint(),
          device.getUserAgent(),
          device.getIpAddress(),
        ));
      } else {
        device.updateLastUsed();
        await this.deviceRepository.save(device);
      }
      await this.cacheService.set(cacheKey, device, 60 * 60); // 1 hour TTL
    }

    return device;
  }
}`
          }
        },
        'infrastructure': {
          'persistence': {
            'typeorm': {
              'entities': {
                'device.orm-entity.ts': `import { Entity, Column, PrimaryColumn, Index } from 'typeorm';

/**
 * Database entity for devices with partitioning support.
 */
@Entity('devices', {
  comment: 'Partitioned by userId for scalability',
})
@Index(['fingerprint'], { unique: true })
@Index(['userId'])
export class DeviceOrmEntity {
  @PrimaryColumn()
  id: string;

  @Column()
  userId: string;

  @Column()
  fingerprint: string; // Encrypted

  @Column()
  userAgent: string;

  @Column()
  ipAddress: string;

  @Column({ default: false })
  isVerified: boolean;

  @Column()
  createdAt: Date;

  @Column()
  lastUsedAt: Date;
}`
              },
              'repositories': {
                'device-typeorm.repository.ts': `import { Injectable, Inject } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { DeviceOrmEntity } from '../entities/device.orm-entity';
import { DeviceRepository } from '../../../domain/repositories/device.repository';
import { Device } from '../../../domain/entities/device.entity';
import { CryptoService } from '../../../../../common/utils/crypto.utils';

@Injectable()
export class DeviceTypeOrmRepository implements DeviceRepository {
  constructor(
    @InjectRepository(DeviceOrmEntity)
    private repository: Repository<DeviceOrmEntity>,
    private cryptoService: CryptoService,
  ) {}

  async findById(id: string): Promise<Device | null> {
    const ormEntity = await this.repository.findOne({
      where: { id },
      select: ['id', 'userId', 'fingerprint', 'userAgent', 'ipAddress', 'isVerified', 'createdAt', 'lastUsedAt'],
    });
    return this.mapToDomain(ormEntity);
  }

  async findByFingerprint(fingerprint: string): Promise<Device | null> {
    const encryptedFingerprint = this.cryptoService.encrypt(fingerprint);
    const ormEntity = await this.repository.findOne({
      where: { fingerprint: encryptedFingerprint },
      select: ['id', 'userId', 'fingerprint', 'userAgent', 'ipAddress', 'isVerified', 'createdAt', 'lastUsedAt'],
    });
    return this.mapToDomain(ormEntity);
  }

  async save(device: Device): Promise<void> {
    const ormEntity = new DeviceOrmEntity();
    ormEntity.id = device.getId();
    ormEntity.userId = device.getUserId();
    ormEntity.fingerprint = this.cryptoService.encrypt(device.getFingerprint());
    ormEntity.userAgent = device.getUserAgent();
    ormEntity.ipAddress = device.getIpAddress();
    ormEntity.isVerified = device.getIsVerified();
    ormEntity.createdAt = device.getCreatedAt();
    ormEntity.lastUsedAt = device.getLastUsedAt();

    await this.repository.upsert(ormEntity, ['id']);
  }

  private mapToDomain(ormEntity: DeviceOrmEntity | null): Device | null {
    if (!ormEntity) return null;
    return new Device({
      id: ormEntity.id,
      userId: ormEntity.userId,
      fingerprint: this.cryptoService.decrypt(ormEntity.fingerprint),
      userAgent: ormEntity.userAgent,
      ipAddress: ormEntity.ipAddress,
    });
  }
}`
              }
            }
          }
        }
      },
      'auth': {
        'auth.module.ts': `import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { JwtModule } from '@nestjs/jwt';
import { ClientsModule, Transport } from '@nestjs/microservices';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { AuthController } from './presentation/controllers/auth.controller';
import { VerifyDeviceUseCase } from './application/use-cases/verify-device.use-case';
import { ConfirmDeviceVerificationUseCase } from './application/use-cases/confirm-device-verification.use-case';
import { VerificationTokenTypeOrmRepository } from './infrastructure/persistence/typeorm/repositories/verification-token-typeorm.repository';
import { NodemailerEmailService } from './infrastructure/services/email/nodemailer-email.service';
import { VerificationTokenOrmEntity } from './infrastructure/persistence/typeorm/entities/verification-token.orm-entity';
import { EmailConsumer } from './infrastructure/kafka/email.consumer';
import { RedisCacheService } from '../../common/services/redis-cache.service';
import { RolesGuard } from '../../common/guards/roles.guard';
import { DeviceModule } from '../device/device.module';

@Module({
  imports: [
    TypeOrmModule.forFeature([VerificationTokenOrmEntity]),
    JwtModule.registerAsync({
      imports: [ConfigModule],
      useFactory: (configService: ConfigService) => ({
        secret: configService.get('app.jwt.secret'),
        signOptions: { expiresIn: configService.get('app.jwt.expiresIn') },
      }),
      inject: [ConfigService],
    }),
    ClientsModule.registerAsync([
      {
        name: 'KAFKA_CLIENT',
        imports: [ConfigModule],
        useFactory: (configService: ConfigService) => ({
          transport: Transport.KAFKA,
          options: {
            client: {
              clientId: configService.get('app.kafka.clientId'),
              brokers: configService.get('app.kafka.brokers'),
            },
            consumer: {
              groupId: 'auth-group',
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
      provide: 'VerificationTokenRepository',
      useClass: VerificationTokenTypeOrmRepository,
    },
    {
      provide: 'EmailService',
      useClass: NodemailerEmailService,
    },
    {
      provide: 'CacheService',
      useClass: RedisCacheService,
    },
  ],
  exports: [VerifyDeviceUseCase, ConfirmDeviceVerificationUseCase],
})
export class AuthModule {}`
,
        'domain': {
          'entities': {
            'verification-token.entity.ts': `import { v4 as uuidv4 } from 'uuid';

/**
 * Domain entity for verification tokens.
 */
export class VerificationToken {
  private id: string;
  private deviceId: string;
  private token: string;
  private expiresAt: Date;

  constructor(props: { id?: string; deviceId: string; token?: string; expiresAt: Date }) {
    this.id = props.id ?? uuidv4();
    this.deviceId = props.deviceId;
    this.token = props.token ?? uuidv4();
    this.expiresAt = props.expiresAt;
  }

  isExpired(): boolean {
    return new Date() > this.expiresAt;
  }

  getId(): string { return this.id; }
  getDeviceId(): string { return this.deviceId; }
  getToken(): string { return this.token; }
  getExpiresAt(): Date { return this.expiresAt; }
}`
          },
          'repositories': {
            'verification-token.repository.ts': `import { VerificationToken } from '../entities/verification-token.entity';
import { Repository } from '../../../../common/interfaces/repository.interface';

export interface VerificationTokenRepository extends Repository<VerificationToken> {
  findByToken(token: string): Promise<VerificationToken | null>;
  deleteById(id: string): Promise<void>;
}`
          },
          'services': {
            'email.service.ts': `export interface EmailService {
  sendVerificationEmail(to: string, token: string, deviceId: string): Promise<void>;
}`
          },
          'events': {
            'verification-initiated.event.ts': `export class VerificationInitiatedEvent {
  constructor(
    public readonly deviceId: string,
    public readonly userEmail: string,
    public readonly token: string,
  ) {}
}`
          }
        },
        'application': {
          'dtos': {
            'login.dto.ts': `import { IsString, IsEmail } from 'class-validator';

export class LoginDto {
  @IsString()
  userId: string;

  @IsEmail()
  email: string;
}`
,
            'verify-device.dto.ts': `import { IsString } from 'class-validator';

export class VerifyDeviceDto {
  @IsString()
  token: string;
}`
          },
          'use-cases': {
            'verify-device.use-case.ts': `import { Injectable, Inject, Logger, BadRequestException } from '@nestjs/common';
import { VerificationTokenRepository } from '../../domain/repositories/verification-token.repository';
import { EmailService } from '../../domain/services/email.service';
import { VerificationToken } from '../../domain/entities/verification-token.entity';
import { ClientKafka } from '@nestjs/microservices';
import { VerificationInitiatedEvent } from '../../domain/events/verification-initiated.event';
import { DeviceRepository } from '../../../device/domain/repositories/device.repository';

@Injectable()
export class VerifyDeviceUseCase {
  private readonly logger = new Logger(VerifyDeviceUseCase.name);

  constructor(
    @Inject('DeviceRepository') private deviceRepository: DeviceRepository,
    @Inject('VerificationTokenRepository') private tokenRepository: VerificationTokenRepository,
    @Inject('EmailService') private emailService: EmailService,
    @Inject('KAFKA_CLIENT') private kafkaClient: ClientKafka,
  ) {}

  async execute(input: { deviceId: string; userEmail: string }): Promise<void> {
    const device = await this.deviceRepository.findById(input.deviceId);
    if (!device) {
      throw new BadRequestException('Device not found');
    }

    if (device.getIsVerified()) {
      this.logger.warn(\`Device \${input.deviceId} already verified\`);
      return;
    }

    const token = new VerificationToken({
      deviceId: input.deviceId,
      expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000), // 24 hours
    });

    await this.tokenRepository.save(token);
    this.logger.log(\`Verification token created for device \${input.deviceId}\`);

    // Emit event for async email sending and audit logging
    this.kafkaClient.emit('verification.initiated', new VerificationInitiatedEvent(
      input.deviceId,
      input.userEmail,
      token.getToken(),
    ));
  }
}`
,
            'confirm-device-verification.use-case.ts': `import { Injectable, Inject, BadRequestException, Logger } from '@nestjs/common';
import { DeviceRepository } from '../../../device/domain/repositories/device.repository';
import { VerificationTokenRepository } from '../../domain/repositories/verification-token.repository';
import { CacheService } from '../../../../common/interfaces/cache.interface';

@Injectable()
export class ConfirmDeviceVerificationUseCase {
  private readonly logger = new Logger(ConfirmDeviceVerificationUseCase.name);

  constructor(
    @Inject('DeviceRepository') private deviceRepository: DeviceRepository,
    @Inject('VerificationTokenRepository') private tokenRepository: VerificationTokenRepository,
    @Inject('CacheService') private cacheService: CacheService,
  ) {}

  async execute(token: string): Promise<void> {
    const verificationToken = await this.tokenRepository.findByToken(token);
    if (!verificationToken || verificationToken.isExpired()) {
      throw new BadRequestException('Invalid or expired token');
    }

    const device = await this.deviceRepository.findById(verificationToken.getDeviceId());
    if (!device) {
      throw new BadRequestException('Device not found');
    }

    device.verify();
    await this.deviceRepository.save(device);
    await this.tokenRepository.deleteById(verificationToken.getId());
    this.logger.log(\`Device \${device.getId()} verified\`);

    // Invalidate cache
    const cacheKey = \`device:\${device.getFingerprint()}\`;
    await this.cacheService.del(cacheKey);
  }
}`
          }
        },
        'infrastructure': {
          'persistence': {
            'typeorm': {
              'entities': {
                'verification-token.orm-entity.ts': `import { Entity, Column, PrimaryColumn, Index } from 'typeorm';

@Entity('verification_tokens')
@Index(['token'], { unique: true })
export class VerificationTokenOrmEntity {
  @PrimaryColumn()
  id: string;

  @Column()
  deviceId: string;

  @Column()
  token: string;

  @Column()
  expiresAt: Date;
}`
              },
              'repositories': {
                'verification-token-typeorm.repository.ts': `import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { VerificationTokenOrmEntity } from '../entities/verification-token.orm-entity';
import { VerificationTokenRepository } from '../../../domain/repositories/verification-token.repository';
import { VerificationToken } from '../../../domain/entities/verification-token.entity';

@Injectable()
export class VerificationTokenTypeOrmRepository implements VerificationTokenRepository {
  constructor(
    @InjectRepository(VerificationTokenOrmEntity)
    private repository: Repository<VerificationTokenOrmEntity>,
  ) {}

  async findById(id: string): Promise<VerificationToken | null> {
    const ormEntity = await this.repository.findOne({
      where: { id },
    });
    return this.mapToDomain(ormEntity);
  }

  async findByToken(token: string): Promise<VerificationToken | null> {
    const ormEntity = await this.repository.findOne({
      where: { token },
    });
    return this.mapToDomain(ormEntity);
  }

  async save(token: VerificationToken): Promise<void> {
    const ormEntity = new VerificationTokenOrmEntity();
    ormEntity.id = token.getId();
    ormEntity.deviceId = token.getDeviceId();
    ormEntity.token = token.getToken();
    ormEntity.expiresAt = token.getExpiresAt();

    await this.repository.save(ormEntity);
  }

  async deleteById(id: string): Promise<void> {
    await this.repository.delete(id);
  }

  private mapToDomain(ormEntity: VerificationTokenOrmEntity | null): VerificationToken | null {
    if (!ormEntity) return null;
    return new VerificationToken({
      id: ormEntity.id,
      deviceId: ormEntity.deviceId,
      token: ormEntity.token,
      expiresAt: ormEntity.expiresAt,
    });
  }
}`
              }
            }
          },
          'services': {
            'email': {
              'nodemailer-email.service.ts': `import { Injectable, Logger } from '@nestjs/common';
import { EmailService } from '../../../domain/services/email.service';
import { ConfigService } from '@nestjs/config';
import { createTransport } from 'nodemailer';
import { CircuitBreaker } from '../../../../common/utils/circuit-breaker';

@Injectable()
export class NodemailerEmailService implements EmailService {
  private readonly logger = new Logger(NodemailerEmailService.name);
  private transporter;
  private circuitBreaker: CircuitBreaker;

  constructor(private configService: ConfigService) {
    this.transporter = createTransport({
      host: this.configService.get('app.email.host'),
      port: this.configService.get('app.email.port'),
      auth: {
        user: this.configService.get('app.email.user'),
        pass: this.configService.get('app.email.pass'),
      },
    });
    this.circuitBreaker = new CircuitBreaker({
      failureThreshold: 5,
      resetTimeout: 60000,
    });
  }

  async sendVerificationEmail(to: string, token: string, deviceId: string): Promise<void> {
    await this.circuitBreaker.execute(async () => {
      await this.transporter.sendMail({
        to,
        subject: 'Verify Your Device',
        html: \`
          <p>Please verify your device by clicking the link below:</p>
          <a href="\${this.configService.get('app.url')}/auth/verify-device?token=\${token}">Verify Device</a>
          <p>Device ID: \${deviceId}</p>
        \`,
      });
      this.logger.log(\`Verification email sent to \${to}\`);
    });
  }
}`
            }
          },
          'kafka': {
            'email.consumer.ts': `import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { Consumer, Kafka } from 'kafkajs';
import { EmailService } from '../../domain/services/email.service';
import { ConfigService } from '@nestjs/config';
import { VerificationInitiatedEvent } from '../../domain/events/verification-initiated.event';

@Injectable()
export class EmailConsumer implements OnModuleInit {
  private readonly logger = new Logger(EmailConsumer.name);
  private consumer: Consumer;

  constructor(
    @Inject('EmailService') private emailService: EmailService,
    private configService: ConfigService,
  ) {
    const kafka = new Kafka({
      clientId: this.configService.get('app.kafka.clientId'),
      brokers: this.configService.get('app.kafka.brokers'),
    });
    this.consumer = kafka.consumer({ groupId: 'email-group' });
  }

  async onModuleInit() {
    await this.consumer.connect();
    await this.consumer.subscribe({ topic: 'verification.initiated', fromBeginning: false });

    await this.consumer.run({
      eachMessage: async ({ message }) => {
        const event = JSON.parse(message.value.toString()) as VerificationInitiatedEvent;
        try {
          await this.emailService.sendVerificationEmail(
            event.userEmail,
            event.token,
            event.deviceId,
          );
          this.logger.log(\`Processed verification email for device \${event.deviceId}\`);
        } catch (error) {
          this.logger.error(\`Failed to send email: \${error.message}\`);
        }
      },
    });
  }
}`
          }
        },
        'presentation': {
          'controllers': {
            'auth.controller.ts': `import { Controller, Post, Body, Get, Query, UseGuards, UseInterceptors, Request, Inject } from '@nestjs/common';
import { DetectDeviceUseCase } from '../../../device/application/use-cases/detect-device.use-case';
import { VerifyDeviceUseCase } from '../../application/use-cases/verify-device.use-case';
import { ConfirmDeviceVerificationUseCase } from '../../application/use-cases/confirm-device-verification.use-case';
import { LoginDto } from '../../application/dtos/login.dto';
import { VerifyDeviceDto } from '../../application/dtos/verify-device.dto';
import { RolesGuard } from '../../../../common/guards/roles.guard';
import { LoggingInterceptor } from '../../../../common/interceptors/logging.interceptor';
import { JwtService } from '@nestjs/jwt';
import { ApiTags, ApiOperation, ApiResponse, ApiBearerAuth } from '@nestjs/swagger';
import { Roles } from '../../../../common/decorators/roles.decorator';

@ApiTags('auth')
@Controller('auth')
@UseInterceptors(LoggingInterceptor)
export class AuthController {
  constructor(
    private detectDeviceUseCase: DetectDeviceUseCase,
    private verifyDeviceUseCase: VerifyDeviceUseCase,
    private confirmDeviceVerificationUseCase: ConfirmDeviceVerificationUseCase,
    private jwtService: JwtService,
  ) {}

  @Post('login')
  @ApiOperation({ summary: 'Authenticate user and detect device' })
  @ApiResponse({ status: 200, description: 'Login successful or verification email sent' })
  async login(@Body() body: LoginDto, @Request() req) {
    const device = await this.detectDeviceUseCase.execute({
      userId: body.userId,
      fingerprint: req.headers['x-device-fingerprint'] || 'unknown', // Assume client generates fingerprint
      userAgent: req.headers['user-agent'] || '',
      ipAddress: req.ip,
    });

    if (!device.getIsVerified()) {
      await this.verifyDeviceUseCase.execute({
        deviceId: device.getId(),
        userEmail: body.email,
      });
      return { message: 'Verification email sent', deviceId: device.getId() };
    }

    const token = this.jwtService.sign({
      userId: body.userId,
      deviceId: device.getId(),
      roles: ['user'],
    });

    return { message: 'Login successful', token };
  }

  @Get('verify-device')
  @ApiOperation({ summary: 'Verify device using token' })
  @ApiResponse({ status: 200, description: 'Device verified successfully' })
  async verifyDevice(@Query() query: VerifyDeviceDto) {
    await this.confirmDeviceVerificationUseCase.execute(query.token);
    return { message: 'Device verified successfully' };
  }

  @Get('protected')
  @UseGuards(RolesGuard)
  @Roles('user')
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Protected endpoint for authenticated users' })
  async protected() {
    return { message: 'Protected resource accessed' };
  }
}`
          }
        }
      }
    },
    'app.module.ts': `import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { TypeOrmModule } from '@nestjs/typeorm';
import { JwtModule } from '@nestjs/jwt';
import { ClientsModule, Transport } from '@nestjs/microservices';
import { DeviceModule } from './modules/device/device.module';
import { AuthModule } from './modules/auth/auth.module';
import appConfig from './config/app.config';
import { DeviceOrmEntity } from './modules/device/infrastructure/persistence/typeorm/entities/device.orm-entity';
import { VerificationTokenOrmEntity } from './modules/auth/infrastructure/persistence/typeorm/entities/verification-token.orm-entity';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      load: [appConfig],
    }),
    TypeOrmModule.forRootAsync({
      useFactory: (configService: ConfigService) => ({
        type: 'postgres',
        host: configService.get('app.db.host'),
        port: configService.get('app.db.port'),
        username: configService.get('app.db.username'),
        password: configService.get('app.db.password'),
        database: configService.get('app.db.name'),
        entities: [DeviceOrmEntity, VerificationTokenOrmEntity],
        synchronize: configService.get('app.env') !== 'production',
        ssl: configService.get('app.env') === 'production' ? { rejectUnauthorized: false } : false,
      }),
      inject: [ConfigService],
    }),
    JwtModule.registerAsync({
      useFactory: (configService: ConfigService) => ({
        secret: configService.get('app.jwt.secret'),
        signOptions: { expiresIn: configService.get('app.jwt.expiresIn') },
      }),
      inject: [ConfigService],
    }),
    ClientsModule.registerAsync([
      {
        name: 'KAFKA_CLIENT',
        useFactory: (configService: ConfigService) => ({
          transport: Transport.KAFKA,
          options: {
            client: {
              clientId: configService.get('app.kafka.clientId'),
              brokers: configService.get('app.kafka.brokers'),
            },
            consumer: {
              groupId: 'auth-group',
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
export class AppModule {}`
,
    'main.ts': `import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ConfigService } from '@nestjs/config';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import { LoggingInterceptor } from './common/interceptors/logging.interceptor';
import { ValidationPipe } from '@nestjs/common';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  const configService = app.get(ConfigService);

  app.useGlobalPipes(new ValidationPipe({ transform: true, whitelist: true }));
  app.useGlobalInterceptors(new LoggingInterceptor());

  const swaggerConfig = new DocumentBuilder()
    .setTitle('Auth Service')
    .setDescription('Device detection and email verification API')
    .setVersion('1.0')
    .addBearerAuth()
    .build();
  const document = SwaggerModule.createDocument(app, swaggerConfig);
  SwaggerModule.setup('api', app, document);

  await app.listen(configService.get('app.port'));
}
bootstrap();`
  },
  'test': {
    'app.e2e-spec.ts': `import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication } from '@nestjs/common';
import * as request from 'supertest';
import { AppModule } from '../src/app.module';

describe('AppController (e2e)', () => {
  let app: INestApplication;

  beforeEach(async () => {
    const moduleFixture: TestingModule = await Test.createTestingModule({
      imports: [AppModule],
    }).compile();

    app = moduleFixture.createNestApplication();
    await app.init();
  });

  it('/ (GET)', () => {
    return request(app.getHttpServer())
      .get('/')
      .expect(200);
  });
});`
  },
  'package.json': `{
  "name": "device-detection-auth-service",
  "version": "0.0.1",
  "description": "Enterprise-grade device detection and email verification service",
  "author": "",
  "private": true,
  "license": "UNLICENSED",
  "scripts": {
    "build": "nest build",
    "format": "prettier --write \\"src/**/*.ts\\" \\"test/**/*.ts\\"",
    "start": "nest start",
    "start:dev": "nest start --watch",
    "start:debug": "nest start --debug --watch",
    "start:prod": "node dist/main",
    "lint": "eslint \\"{src,apps,libs,test}/**/*.ts\\" --fix",
    "test": "jest",
    "test:watch": "jest --watch",
    "test:cov": "jest --coverage",
    "test:debug": "node --inspect-brk -r tsconfig-paths/register -r ts-node/register node_modules/.bin/jest --runInBand",
    "test:e2e": "jest --config ./test/jest-e2e.json"
  },
  "dependencies": {
    "@nestjs/common": "^10.0.0",
    "@nestjs/config": "^3.0.0",
    "@nestjs/core": "^10.0.0",
    "@nestjs/jwt": "^10.1.0",
    "@nestjs/microservices": "^10.0.0",
    "@nestjs/platform-express": "^10.0.0",
    "@nestjs/swagger": "^7.0.0",
    "@nestjs/typeorm": "^10.0.0",
    "class-transformer": "^0.5.1",
    "class-validator": "^0.14.0",
    "ioredis": "^5.3.2",
    "kafkajs": "^2.2.4",
    "nodemailer": "^6.9.3",
    "pg": "^8.11.1",
    "reflect-metadata": "^0.1.13",
    "rxjs": "^7.8.1",
    "typeorm": "^0.3.17",
    "uuid": "^9.0.0"
  },
  "devDependencies": {
    "@nestjs/cli": "^10.0.0",
    "@nestjs/schematics": "^10.0.0",
    "@nestjs/testing": "^10.0.0",
    "@types/express": "^4.17.17",
    "@types/jest": "^29.5.2",
    "@types/node": "^20.3.1",
    "@types/nodemailer": "^6.4.8",
    "@types/supertest": "^2.0.12",
    "@types/uuid": "^9.0.2",
    "@typescript-eslint/eslint-plugin": "^5.59.11",
    "@typescript-eslint/parser": "^5.59.11",
    "eslint": "^8.42.0",
    "eslint-config-prettier": "^8.8.0",
    "eslint-plugin-prettier": "^4.2.1",
    "jest": "^29.5.0",
    "prettier": "^2.8.8",
    "source-map-support": "^0.5.21",
    "supertest": "^6.3.3",
    "ts-jest": "^29.1.0",
    "ts-loader": "^9.4.3",
    "ts-node": "^10.9.1",
    "tsconfig-paths": "^4.2.0",
    "typescript": "^5.1.3"
  },
  "jest": {
    "moduleFileExtensions": [
      "js",
      "json",
      "ts"
    ],
    "rootDir": "src",
    "testRegex": ".*\\.spec\\.ts$",
    "transform": {
      "^.+\\.(t|j)s$": "ts-jest"
    },
    "collectCoverageFrom": [
      "**/*.(t|j)s"
    ],
    "coverageDirectory": "../coverage",
    "testEnvironment": "node"
  }
}`,
  'nest-cli.json': `{
  "$schema": "https://json.schemastore.org/nest-cli",
  "collection": "@nestjs/schematics",
  "sourceRoot": "src",
  "compilerOptions": {
    "deleteOutDir": true
  }
}`,
  'tsconfig.json': `{
  "compilerOptions": {
    "module": "commonjs",
    "declaration": true,
    "removeComments": true,
    "emitDecoratorMetadata": true,
    "experimentalDecorators": true,
    "allowSyntheticDefaultImports": true,
    "target": "ES2021",
    "sourceMap": true,
    "outDir": "./dist",
    "baseUrl": "./",
    "incremental": true,
    "skipLibCheck": true,
    "strictNullChecks": true,
    "noImplicitAny": true,
    "strictBindCallApply": true,
    "forceConsistentCasingInFileNames": true,
    "noFallthroughCasesInSwitch": true
  }
}`,
  '.env.example': `NODE_ENV=development
PORT=3000
APP_URL=http://localhost:3000

# Database
DB_HOST=localhost
DB_PORT=5432
DB_USERNAME=postgres
DB_PASSWORD=postgres
DB_NAME=auth_service

# JWT
JWT_SECRET=your-jwt-secret

# Redis
REDIS_URL=redis://localhost:6379

# Kafka
KAFKA_BROKERS=localhost:9092

# Email
EMAIL_PROVIDER=nodemailer
EMAIL_HOST=smtp.example.com
EMAIL_PORT=587
EMAIL_USER=user@example.com
EMAIL_PASS=password

# Encryption
ENCRYPTION_KEY=32-bytes-encryption-key-here
`
};

// Function to create directories recursively
function createDirectories(basePath, structure, currentPath = '') {
  for (const [key, value] of Object.entries(structure)) {
    const newPath = path.join(currentPath, key);
    const fullPath = path.join(basePath, newPath);
    
    if (typeof value === 'object') {
      // Create directory
      if (!fs.existsSync(fullPath)) {
        fs.mkdirSync(fullPath, { recursive: true });
        console.log(`Created directory: ${newPath}`);
      }
      
      // Recursively create subdirectories and files
      createDirectories(basePath, value, newPath);
    } else {
      // Create file with content
      fs.writeFileSync(fullPath, value);
      console.log(`Created file: ${newPath}`);
    }
  }
}

// Create a temporary directory for the project
const projectDir = path.join('/tmp', 'nestjs-device-detection');
if (!fs.existsSync(projectDir)) {
  fs.mkdirSync(projectDir, { recursive: true });
}

// Create the project structure
createDirectories(projectDir, projectStructure);

// Add missing imports to email.consumer.ts
const emailConsumerPath = path.join(projectDir, 'src/modules/auth/infrastructure/kafka/email.consumer.ts');
const emailConsumerContent = fs.readFileSync(emailConsumerPath, 'utf8');
const updatedEmailConsumerContent = emailConsumerContent.replace('constructor(', 'constructor(\n    @Inject(\'EmailService\')');
fs.writeFileSync(emailConsumerPath, updatedEmailConsumerContent);

console.log('\n--- Project Structure Summary ---');
console.log('The NestJS application has been refactored into the following structure:');
console.log('1. Domain-Driven Design (DDD) architecture');
console.log('2. Hexagonal architecture with clear separation of concerns');
console.log('3. Modules organized by feature (device, auth)');
console.log('4. Each module follows the Clean Architecture pattern:');
console.log('   - Domain layer (entities, repositories interfaces, events)');
console.log('   - Application layer (use cases, DTOs)');
console.log('   - Infrastructure layer (repositories implementations, services)');
console.log('   - Presentation layer (controllers)');
console.log('\nThe application implements:');
console.log('- Device detection and verification');
console.log('- Email verification for new devices');
console.log('- JWT-based authentication');
console.log('- Role-based authorization');
console.log('- Circuit breaker pattern for external services');
console.log('- Event-driven architecture with Kafka');
console.log('- Caching with Redis');
console.log('- Data encryption for sensitive information');

console.log('\nTo run this application:');
console.log('1. Install dependencies: npm install');
console.log('2. Configure environment variables (copy .env.example to .env)');
console.log('3. Start the application: npm run start:dev');
