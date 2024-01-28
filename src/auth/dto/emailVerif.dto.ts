import { ApiProperty, ApiPropertyOptional } from "@nestjs/swagger"
import { IsEmail, IsNotEmpty, IsOptional, IsString } from "class-validator"
export class EmailVerifDto
{
  @ApiProperty({
    type: String,
    description: 'Propriété requise',
  })
  @IsEmail()
  @IsNotEmpty()
  email: string

  @ApiPropertyOptional({
    type: String,
    description: 'Propriété optionnelle',
  })
  @IsString()
  @IsNotEmpty()
  @IsOptional()
  mode?: string
}