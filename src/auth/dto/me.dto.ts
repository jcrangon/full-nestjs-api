import { Role } from "@prisma/client"
import { ApiProperty, ApiPropertyOptional } from "@nestjs/swagger"
import { IsEmail, IsNotEmpty, IsOptional, IsString, IsNumber, IsEnum, IsBoolean, IsDate } from "class-validator"

export class MeDto 
{
  @ApiProperty({
    type: Number,
    description: 'Propriété requise',
  })
  @IsNumber()
  @IsNotEmpty()
  id: number

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
  firstName?: string

  @ApiPropertyOptional({
    type: String,
    description: 'Propriété optionnelle',
  })
  @IsString()
  @IsNotEmpty()
  @IsOptional()
  lastName?: string

  @ApiProperty({
    type: Array,
    description: 'Propriété requise',
  })
  @IsEnum(Role)
  @IsNotEmpty()
  roles: Role[]

  @ApiProperty({
    type: Boolean,
    description: 'Propriété requise',
  })
  @IsBoolean()
  @IsNotEmpty()
  verified: boolean

  @ApiProperty({
    type: Date,
    description: 'Propriété requise',
  })
  @IsDate()
  @IsNotEmpty()
  created_at: Date
  updated_at: Date
}