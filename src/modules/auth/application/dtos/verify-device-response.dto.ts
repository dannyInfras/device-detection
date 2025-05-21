import { ApiProperty } from "@nestjs/swagger"

export class VerifyDeviceResponseDto {
  @ApiProperty({
    description: 'Response message',
    example: 'Device verified successfully'
  })
  message: string
} 