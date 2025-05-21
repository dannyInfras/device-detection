import { Controller, Get, Query, UseGuards, UseInterceptors } from "@nestjs/common"
import type { DetectDeviceUseCase } from "../../../device/application/use-cases/detect-device.use-case"
import type { VerifyDeviceUseCase } from "../../application/use-cases/verify-device.use-case"
import type { ConfirmDeviceVerificationUseCase } from "../../application/use-cases/confirm-device-verification.use-case"
import type { LoginDto } from "../../application/dtos/login.dto"
import type { VerifyDeviceDto } from "../../application/dtos/verify-device.dto"
import { RolesGuard } from "../../../../common/guards/roles.guard"
import { LoggingInterceptor } from "../../../../common/interceptors/logging.interceptor"
import type { JwtService } from "@nestjs/jwt"
import { ApiTags, ApiOperation, ApiResponse, ApiBearerAuth } from "@nestjs/swagger"
import { Roles } from "../../../../common/decorators/roles.decorator"

@ApiTags("auth")
@Controller("auth")
@UseInterceptors(LoggingInterceptor)
export class AuthController {
  constructor(
    private detectDeviceUseCase: DetectDeviceUseCase,
    private verifyDeviceUseCase: VerifyDeviceUseCase,
    private confirmDeviceVerificationUseCase: ConfirmDeviceVerificationUseCase,
    private jwtService: JwtService,
  ) {}

  login(body: LoginDto, req) {
    const device = this.detectDeviceUseCase.execute({
      userId: body.userId,
      fingerprint: req.headers["x-device-fingerprint"] || "unknown", // Assume client generates fingerprint
      userAgent: req.headers["user-agent"] || "",
      ipAddress: req.ip,
    })

    if (!device.getIsVerified()) {
      this.verifyDeviceUseCase.execute({
        deviceId: device.getId(),
        userEmail: body.email,
      })
      return { message: "Verification email sent", deviceId: device.getId() }
    }

    const token = this.jwtService.sign({
      userId: body.userId,
      deviceId: device.getId(),
      roles: ["user"],
    })

    return { message: "Login successful", token }
  }

  @Get('verify-device')
  @ApiOperation({ summary: 'Verify device using token' })
  @ApiResponse({ status: 200, description: 'Device verified successfully' })
  async verifyDevice(@Query() query: VerifyDeviceDto) {
    await this.confirmDeviceVerificationUseCase.execute(query.token);
    return { message: 'Device verified successfully' };
  }

  @Get("protected")
  @UseGuards(RolesGuard)
  @Roles("user")
  @ApiBearerAuth()
  @ApiOperation({ summary: "Protected endpoint for authenticated users" })
  async protected() {
    return { message: "Protected resource accessed" }
  }
}
