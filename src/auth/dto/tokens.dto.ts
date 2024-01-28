import { ApiProperty } from "@nestjs/swagger"

export class TokenDto
{
  @ApiProperty({
    type: String,
    description: 'This is a required property',
  })
  accessToken?: string

  @ApiProperty({
    type: String,
    description: 'This is a required property',
  })
  refreshToken: string
}