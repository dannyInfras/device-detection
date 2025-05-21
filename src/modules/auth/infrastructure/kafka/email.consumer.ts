import { Injectable, Logger, type OnModuleInit } from "@nestjs/common"
import type { EmailService } from "../../domain/services/email.service"
import type { ConfigService } from "@nestjs/config"

@Injectable()
export class EmailConsumer implements OnModuleInit {
  private readonly logger = new Logger(EmailConsumer.name)

  constructor(
    private emailService: EmailService,
    private configService: ConfigService,
  ) {
    this.logger.log('Email Consumer initialized - Kafka connection is mocked');
  }

  async onModuleInit() {
    this.logger.log('Email Consumer started - Kafka connection is mocked, no real connections will be made');
    this.logger.log('To resume normal Kafka operation, modify /etc/hosts to add "127.0.0.1 kafka" or update the code to use localhost instead');
  }
}
