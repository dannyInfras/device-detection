import { Injectable, Logger, UnauthorizedException, Inject } from "@nestjs/common"
import type { UserRepository } from "../../domain/repositories/user.repository"

@Injectable()
export class LoginUseCase {
  private readonly logger = new Logger(LoginUseCase.name)

  constructor(
    @Inject("UserRepository")
    private userRepository: UserRepository
  ) {}

  async execute(input: { email: string; password: string }): Promise<{ userId: string; email: string }> {
    const user = await this.userRepository.findByEmail(input.email)
    
    if (!user || !user.validatePassword(input.password)) {
      throw new UnauthorizedException("Invalid email or password")
    }

    this.logger.log(`User logged in: ${user.getId()}`)

    return {
      userId: user.getId(),
      email: user.getEmail()
    }
  }
} 