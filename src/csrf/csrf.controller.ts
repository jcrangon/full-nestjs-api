import { Controller, Get, Res, Req, Version } from "@nestjs/common";
import { CsrfService } from "./csrf.service";
import { Request, Response } from "express";
import { ApiTags } from "@nestjs/swagger";

@ApiTags('Csrf')
@Controller('csrf-token')
export class CsrfController
{
  constructor(
    private readonly csrfService: CsrfService
  ) {}

  @Get('get')
  @Version('1')
  getCsrfToken(@Req() req: Request, @Res({passthrough: true}) res: Response ) {
    return this.csrfService.getToken(req, res)
  }

}