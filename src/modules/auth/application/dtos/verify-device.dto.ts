import { IsString } from "class-validator"

export class VerifyDeviceDto {
  @IsString()
  token: string
}
