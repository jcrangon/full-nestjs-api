import { TokenDto } from './dto/tokens.dto';
import { ConfigService } from '@nestjs/config';
import { Body, Controller, Post, Res, UseGuards, Req, Get, Param, Version } from "@nestjs/common";
import { AuthService } from "./auth.service";
import { AuthDto } from "./dto";
import { CsrfGuard } from "../csrf/guards/csrf.guard";
import { Request, Response } from "express";
import { AccessTokenGuard } from "./guards/accessTokenGuard.guard";
import { RefreshTokenGuard } from "./guards/refreshTokenGuard.guard";
import { Throttle, ThrottlerGuard } from "@nestjs/throttler";
import { GetJwtUser, Getme } from "./decorators";
import { ApiBearerAuth, ApiBody, ApiCreatedResponse, ApiForbiddenResponse, ApiHeader, ApiParam, ApiResponse, ApiTags } from '@nestjs/swagger';
import { EmailVerifDto } from './dto/emailVerif.dto';
import { BasicResponse } from './dto/basicResponse.dto';
import { PasswordResetDto } from './dto/passwordReset.dto';
import { MeDto } from './dto/me.dto';
/*
import { Role } from './enums/role.enum';
import { Roles } from './decorators/roles.decorator';
import { RolesGuard } from './guards/roles.guard';
*/

@ApiBearerAuth()
@ApiTags('Auth')
@Controller('auth')
export class AuthController
{
  constructor(
    private readonly authService: AuthService,
    private config: ConfigService
  ) {}


  @UseGuards(CsrfGuard, ThrottlerGuard)
  @Post('signup/:mode?')
  @Version('1')
  @ApiHeader({
    name: 'x-csrf-token',
    description: 'Csrf Token',
    required: true,
  })
  @ApiParam({
    name: "mode",
    description: "Mode de confimation de compte. si mode = 'mobile' => l'email contiendra un code, sinon il contiendra un lien.",
    required: false,
  })
  @ApiBody({
    description: 'User credentials',
    type: AuthDto,
  })
  @ApiCreatedResponse({
    status: 201,
    description: 'Created Succesfully',
    type: TokenDto,
    isArray: false,
  })
  @ApiForbiddenResponse({ 
    status: 403, 
    description: 'Forbidden'
  })
  async signup(@Body() dto: AuthDto, @Res({passthrough: true}) res: Response, @Param() param:{mode?: string}): Promise<TokenDto> {
    console.log(dto);
    return await this.authService.signup(dto, res, param)
  }






  @UseGuards(ThrottlerGuard)
  @Get('confirm/:email/:token/:mode?')
  @Version('1')
  @ApiParam({
    name: "mode",
    description: "Mode de confimation de compte. si mode = 'mobile' => l'email contiendra un code, sinon il contiendra un lien.",
    required: false,
  })
  @ApiParam({
    name: "token",
    description: "Token transmis dans l'email",
    required: true,
  })
  @ApiParam({
    name: "email",
    description: "email de l'utilisateur à vérifier",
    required: true,
  })
  @ApiResponse({
    status: 200,
    type: BasicResponse
  })
  @ApiForbiddenResponse({ 
    status: 403, 
    description: 'Forbidden'
  })
  async verifyEmail(@Param() param:{email: string, token: string, mode?: string}, @Res({passthrough: true}) res: Response): Promise<BasicResponse | void> {
   
    const emailAlreadyVerified = await this.authService.EmailAlreaddyVerified(param.email)

    if(emailAlreadyVerified){
      if(param.mode && param.mode === 'mobile') {
        return {
          message: 'Email already verified'
        }
      }
      return res.redirect(`${this.config.get<string>('FRONTEND_URL')}${this.config.get<string>('FRONT_END_EMAIL_VERIF_SUCCESS_URI')}`)
    }

    const accountIsActive = await this.authService.accountIsActive(param.email)

    if(!accountIsActive){
      if(param.mode && param.mode === 'mobile') {
        return {
          message: 'Account suspended'
        }
      }
      return res.redirect(`${this.config.get<string>('FRONTEND_URL')}${this.config.get<string>('FRONT_ACCOUNT_SUSPENDED_URI')}`)
    }

    
    const verifyEmail = await this.authService.verifyEmail(param)

    if(verifyEmail) {
      if(param.mode && param.mode === 'mobile') {
        return {
          message: 'Email verification successful'
        }
      }
      return res.redirect(`${this.config.get<string>('FRONTEND_URL')}${this.config.get<string>('FRONT_END_EMAIL_VERIF_SUCCESS_URI')}`)

    } else {
      if(param.mode && param.mode === 'mobile') {
        return {
          message: 'Email verification failed'
        }
      }
      return res.redirect(`${this.config.get<string>('FRONTEND_URL')}${this.config.get<string>('FRONT_END_EMAIL_VERIF_FAIL_URI')}`)
      
    }
  }




  @UseGuards(ThrottlerGuard)
  @Post('email-verification/resend')
  @Version('1')
  @ApiBody({
    description: 'User identification',
    type: EmailVerifDto,
  })
  @ApiResponse({
    status: 200,
    type: BasicResponse
  })
  @ApiForbiddenResponse({ 
    status: 403, 
    description: 'Forbidden'
  })
  async EmailVerificationResend(@Body() body: EmailVerifDto): Promise<BasicResponse> {
    console.log(body.email)
    return await this.authService.emailVerificationResend(body)
  }




  @UseGuards(ThrottlerGuard)
  @Get('forgotten-password/:email/:mode?')
  @Version('1')
  @ApiParam({
    name: "mode",
    description: "Mode de confimation de compte. si mode = 'mobile' => l'email contiendra un code, sinon il contiendra un lien.",
    required: false,
  })
  @ApiParam({
    name: "email",
    description: "Email de l'utilisateur",
    required: true,
  })
  @ApiResponse({
    status: 200,
    type: BasicResponse
  })
  @ApiForbiddenResponse({ 
    status: 403, 
    description: 'Forbidden'
  })
  async forgotPassSendEmail(@Param() param: EmailVerifDto): Promise<BasicResponse> {
    return await this.authService.forgotPassSendEmail(param)
  }





  @UseGuards(ThrottlerGuard)
  @Post('forgotten-password/reset')
  @Version('1')
  @ApiResponse({
    status: 200,
    type: BasicResponse
  })
  @ApiForbiddenResponse({ 
    status: 403, 
    description: 'Forbidden'
  })
  async resetPassword(@Body() body: PasswordResetDto): Promise<BasicResponse> {
    return await this.authService.resetPassword(body)
  }




  @UseGuards(CsrfGuard, ThrottlerGuard)
  @Post('signin')
  @Version('1')
  @ApiHeader({
    name: 'x-csrf-token',
    description: 'Csrf Token',
    required: true,
  })
  @ApiBody({
    description: 'User credentials',
    type: AuthDto,
  })
  @ApiCreatedResponse({
    status: 200,
    description: 'Connexion réussie',
    type: TokenDto,
    isArray: false,
  })
  @ApiForbiddenResponse({ 
    status: 403, 
    description: 'Forbidden'
  })
  async signin(@Body() dto: AuthDto, @Res({passthrough: true}) res: Response): Promise<TokenDto> {
    return await this.authService.signin(dto, res)
  }





  @UseGuards(AccessTokenGuard)
  @Post('logout')
  @Version('1')
  @ApiResponse({
    status: 200,
    type: BasicResponse
  })
  @ApiForbiddenResponse({ 
    status: 403, 
    description: 'Forbidden'
  })
  async logout(@Req() req: Request): Promise<BasicResponse> {
    return await this.authService.logout(parseInt(req['user']['sub']))
  }




  @Throttle({default: { limit: 6, ttl: 1000}})
  @UseGuards(RefreshTokenGuard, ThrottlerGuard)
  @Post('refresh')
  @Version('1')
  @ApiResponse({
    status: 200,
    type: TokenDto
  })
  @ApiForbiddenResponse({ 
    status: 403, 
    description: 'Forbidden'
  })
  async refreshToken(@Req() req: Request, @Res({passthrough:true}) res: Response): Promise<TokenDto> {
    const userId = parseInt(req['user']['sub'])
    const refresh = req['user']['refreshToken']

    return await this.authService.refreshTokens(
      userId,
      refresh,
      res 
    )
  }

  // le endpoint suivant utilise un decorateur ET
  // un service:

  // @UseGuards(AccessTokenGuard, RolesGuard)
  // @Roles(Role.User)
  @UseGuards(AccessTokenGuard)
  @Get('me')
  @Version('1')
  @ApiResponse({
    status: 200,
    type: MeDto
  })
  @ApiForbiddenResponse({ 
    status: 403, 
    description: 'Forbidden'
  })
  async getMe(@GetJwtUser() jwtUser: any): Promise<MeDto> {
    return await this.authService.getMe(jwtUser)
  }


  // Le endpoint suivant n'utilise qu'un décorateur de parametres:
  @UseGuards(AccessTokenGuard)
  @Get('me2')
  @Version('1')
  @ApiResponse({
    status: 200,
    type: MeDto
  })
  @ApiForbiddenResponse({ 
    status: 403, 
    description: 'Forbidden'
  })
  getMe2(@Getme() user: any): MeDto {
    return user
  }

}