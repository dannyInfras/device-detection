import { ApiProperty } from "@nestjs/swagger"

export class LoginResponseDto {
  @ApiProperty({
    description: 'Response message',
    example: 'Login successful'
  })
  message: string

  @ApiProperty({
    description: 'JSON Web Token for authorization',
    example: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
    required: false
  })
  token?: string

  @ApiProperty({
    description: 'Device ID that needs verification',
    example: '123e4567-e89b-12d3-a456-426614174000',
    required: false
  })
  deviceId?: string
} 