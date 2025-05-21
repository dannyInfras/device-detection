import { ApiProperty } from "@nestjs/swagger"

export class ApiResponseDto<T> {
  @ApiProperty({
    description: 'Response status message',
    example: 'Success'
  })
  message: string

  @ApiProperty({
    description: 'Response data',
    example: {},
    required: false
  })
  data?: T

  @ApiProperty({
    description: 'Error details if any',
    example: null,
    required: false
  })
  error?: string | string[]

  constructor(message: string, data?: T, error?: string | string[]) {
    this.message = message
    this.data = data
    this.error = error
  }
}

export class ErrorResponseDto {
  @ApiProperty({
    description: 'Error status message',
    example: 'Error'
  })
  message: string

  @ApiProperty({
    description: 'Error details',
    example: ['Email is required', 'Password must be at least 8 characters']
  })
  error: string | string[]

  constructor(message: string, error: string | string[]) {
    this.message = message
    this.error = error
  }
} 