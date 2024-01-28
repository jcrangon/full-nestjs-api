import { ApiResponseProperty } from "@nestjs/swagger";

export class BasicResponse 
{
  @ApiResponseProperty({
    type: String,
  })
  message: string
}