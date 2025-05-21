import { IsString } from "class-validator"
import { ApiProperty } from "@nestjs/swagger"

export class VerifyDeviceDto {
  @ApiProperty({
    description: 'Device verification token',
    example: 'a1b2c3d4-5678-90ab-cdef-ghijklmnopqr'
  })
  @IsString()
  token: string
}
