import { Controller, Get, Query, UseGuards, UseInterceptors, Post, Body, Req, Inject } from "@nestjs/common"
import { DetectDeviceUseCase } from "../../../device/application/use-cases/detect-device.use-case"
import { VerifyDeviceUseCase } from "../../application/use-cases/verify-device.use-case"
import { ConfirmDeviceVerificationUseCase } from "../../application/use-cases/confirm-device-verification.use-case"
import { RegisterUseCase } from "../../application/use-cases/register.use-case"
import { LoginUseCase } from "../../application/use-cases/login.use-case"
import { LoginDto } from "../../application/dtos/login.dto"
import { RegisterDto } from "../../application/dtos/register.dto"
import { VerifyDeviceDto } from "../../application/dtos/verify-device.dto"
import { LoginResponseDto } from "../../application/dtos/login-response.dto"
import { RegisterResponseDto } from "../../application/dtos/register-response.dto"
import { VerifyDeviceResponseDto } from "../../application/dtos/verify-device-response.dto"
import { RolesGuard } from "../../../../common/guards/roles.guard"
import { LoggingInterceptor } from "../../../../common/interceptors/logging.interceptor"
import { JwtService } from "@nestjs/jwt"
import { ApiTags, ApiOperation, ApiResponse, ApiBearerAuth } from "@nestjs/swagger"
import { Roles } from "../../../../common/decorators/roles.decorator"
import { Request } from "express"

@ApiTags("auth")
@Controller("auth")
@UseInterceptors(LoggingInterceptor)
export class AuthController {
  constructor(
    @Inject(DetectDeviceUseCase)
    private detectDeviceUseCase: DetectDeviceUseCase,
    @Inject(VerifyDeviceUseCase)
    private verifyDeviceUseCase: VerifyDeviceUseCase,
    @Inject(ConfirmDeviceVerificationUseCase)
    private confirmDeviceVerificationUseCase: ConfirmDeviceVerificationUseCase,
    @Inject(RegisterUseCase)
    private registerUseCase: RegisterUseCase,
    @Inject(LoginUseCase)
    private loginUseCase: LoginUseCase,
    @Inject(JwtService)
    private jwtService: JwtService,
  ) {}

  @Post('register')
  @ApiOperation({ summary: 'Register a new user' })
  @ApiResponse({ status: 201, description: 'User registered successfully', type: RegisterResponseDto })
  @ApiResponse({ status: 400, description: 'Bad request - Email already exists' })
  async register(@Body() body: RegisterDto): Promise<RegisterResponseDto> {
    const result = await this.registerUseCase.execute({
      email: body.email,
      password: body.password,
      fullName: body.fullName
    });
    
    return { message: "User registered successfully", userId: result.userId };
  }

  @Post('login')
  @ApiOperation({ summary: 'Login a user with device detection' })
  @ApiResponse({ status: 200, description: 'Login successful or verification required', type: LoginResponseDto })
  @ApiResponse({ status: 401, description: 'Unauthorized - Invalid credentials' })
  async login(@Body() body: LoginDto, @Req() req: Request): Promise<LoginResponseDto> {
    // Authenticate user with email/password
    const user = await this.loginUseCase.execute({
      email: body.email,
      password: body.password
    });

    // Detect the device
    const device = await this.detectDeviceUseCase.execute({
      userId: user.userId,
      fingerprint: req.headers["x-device-fingerprint"]?.toString() || "unknown",
      userAgent: req.headers["user-agent"]?.toString() || "",
      ipAddress: req.ip || "",
    });

    // If device is not verified, send verification email
    if (!device.getIsVerified()) {
      await this.verifyDeviceUseCase.execute({
        deviceId: device.getId(),
        userEmail: user.email,
      });
      return { message: "Verification email sent", deviceId: device.getId() };
    }

    // Generate JWT token with user info and device info
    const token = this.jwtService.sign({
      userId: user.userId,
      email: user.email,
      deviceId: device.getId(),
      roles: ["user"],
    });

    return { message: "Login successful", token };
  }

  @Get('verify-device')
  @ApiOperation({ summary: 'Verify device using token' })
  @ApiResponse({ status: 200, description: 'Device verified successfully', type: VerifyDeviceResponseDto })
  async verifyDevice(@Query() query: VerifyDeviceDto): Promise<VerifyDeviceResponseDto> {
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
