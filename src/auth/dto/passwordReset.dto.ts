import { ApiProperty } from "@nestjs/swagger"
import { IsEmail, IsNotEmpty, IsOptional, IsString } from "class-validator"

export class PasswordResetDto
{
  @ApiProperty({
    type: String,
    description: 'Propriété requise',
  })
  @IsEmail()
  @IsNotEmpty()
  email: string

  @ApiProperty({
    type: String,
    description: 'Propriété requise',
  })
  @IsString()
  @IsNotEmpty()
  token: string

  @ApiProperty({
    type: String,
    description: 'Propriété requise',
  })
  @IsString()
  @IsNotEmpty()
  password: string
}