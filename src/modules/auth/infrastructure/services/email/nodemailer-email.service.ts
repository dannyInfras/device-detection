import { Injectable, Logger, Inject } from "@nestjs/common"
import type { EmailService } from "../../../domain/services/email.service"
import { ConfigService } from "@nestjs/config"
import { createTransport } from "nodemailer"
import { CircuitBreaker } from "../../../../../common/utils/circuit-breaker"

@Injectable()
export class NodemailerEmailService implements EmailService {
  private readonly logger = new Logger(NodemailerEmailService.name)
  private transporter
  private circuitBreaker: CircuitBreaker

  constructor(
    @Inject(ConfigService)
    private configService: ConfigService
  ) {
    this.transporter = createTransport({
      host: this.configService.get("app.email.host"),
      port: this.configService.get("app.email.port"),
      auth: {
        user: this.configService.get("app.email.user"),
        pass: this.configService.get("app.email.pass"),
      },
    })
    this.circuitBreaker = new CircuitBreaker({
      failureThreshold: 5,
      resetTimeout: 60000,
    })
  }

  async sendVerificationEmail(to: string, token: string, deviceId: string): Promise<void> {
    await this.circuitBreaker.execute(async () => {
      await this.transporter.sendMail({
        to,
        subject: "Verify Your Device",
        html: `
          <p>Please verify your device by clicking the link below:</p>
          <a href="${this.configService.get("app.url")}/auth/verify-device?token=${token}">Verify Device</a>
          <p>Device ID: ${deviceId}</p>
        `,
      })
      this.logger.log(`Verification email sent to ${to}`)
    })
  }
}
