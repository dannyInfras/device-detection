import { IsString, IsEmail } from "class-validator"

export class LoginDto {
  @IsString()
  userId: string

  @IsEmail()
  email: string
}
