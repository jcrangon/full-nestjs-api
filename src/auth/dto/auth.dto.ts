import { ApiProperty } from "@nestjs/swagger"
import { IsEmail, IsNotEmpty, IsString, IsOptional } from "class-validator"

export class AuthDto 
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
  password: string

  @IsString()
  @IsNotEmpty()
  @IsOptional()
  refreshToken?: string

}