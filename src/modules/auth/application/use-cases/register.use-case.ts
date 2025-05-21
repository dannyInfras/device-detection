import { Injectable, Logger, BadRequestException, Inject } from "@nestjs/common"
import { User } from "../../domain/entities/user.entity"
import type { UserRepository } from "../../domain/repositories/user.repository"

@Injectable()
export class RegisterUseCase {
  private readonly logger = new Logger(RegisterUseCase.name)

  constructor(
    @Inject("UserRepository")
    private userRepository: UserRepository
  ) {}

  async execute(input: { email: string; password: string; fullName: string }): Promise<{ userId: string }> {
    const existingUser = await this.userRepository.findByEmail(input.email)
    if (existingUser) {
      throw new BadRequestException("User with this email already exists")
    }

    const user = new User({
      email: input.email,
      password: input.password,
      fullName: input.fullName
    })

    await this.userRepository.save(user)
    this.logger.log(`User registered with ID ${user.getId()}`)

    return { userId: user.getId() }
  }
} 