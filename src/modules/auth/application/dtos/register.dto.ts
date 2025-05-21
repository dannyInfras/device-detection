import { IsString, IsEmail, MinLength, IsOptional } from "class-validator"
import { ApiProperty } from "@nestjs/swagger"

export class RegisterDto {
  @ApiProperty({
    description: 'User email address',
    example: 'user@example.com'
  })
  @IsEmail()
  email: string

  @ApiProperty({
    description: 'User password',
    example: 'password123'
  })
  @IsString()
  @MinLength(8)
  password: string
  
  @ApiProperty({
    description: 'Full name of the user',
    example: 'John Doe'
  })
  @IsString()
  fullName: string
} 