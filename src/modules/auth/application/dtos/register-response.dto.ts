import { ApiProperty } from "@nestjs/swagger"

export class RegisterResponseDto {
  @ApiProperty({
    description: 'Response message',
    example: 'User registered successfully'
  })
  message: string

  @ApiProperty({
    description: 'ID of the newly created user',
    example: '123e4567-e89b-12d3-a456-426614174000'
  })
  userId: string
} 