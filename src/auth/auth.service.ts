import { ForbiddenException, Injectable } from "@nestjs/common";
import { PrismaService } from "../prisma/prisma.service";
import * as argon2 from "argon2";
import { AuthDto } from "./dto";
import { PrismaClientKnownRequestError } from "@prisma/client/runtime/library";
import { JwtService } from "@nestjs/jwt";
import { ConfigService } from "@nestjs/config";
import { Response } from "express";
import { TypedEventEmitter } from "../event-emitter/typed-event-emitter.class";
import { ValidityInterface } from "config/interfaces/validity.interface";
import { Role } from "@prisma/client";
import { TokenDto } from "./dto/tokens.dto";
import { EmailVerifDto } from "./dto/emailVerif.dto";
import { BasicResponse } from "./dto/basicResponse.dto";
import { PasswordResetDto } from "./dto/passwordReset.dto";
import { MeDto } from "./dto/me.dto";

@Injectable()
export class AuthService
{
  constructor(
    private readonly prismaService: PrismaService,
    private jwtService: JwtService,
    private config: ConfigService,
    private eventEmitter: TypedEventEmitter
  ) {}

  private token_mode = this.config.get<string>('TOKEN_MODE_COOKIE')
  private frontendDomain = this.config.get<string>('FRONTEND_DOMAIN')
  
  async signup(
    dto: AuthDto,
    res: Response,
    param: {mode?: string}
  ): Promise<TokenDto> {
    // generer le hash
    const hash = await argon2.hash(dto.password)

    // enregistrer le nouvel utilisateur dans la db
    try {
      const user = await this.prismaService.user.create({
        data: {
          email: dto.email,
          hash: hash,
          firstName: null,
          lastName: null
        }
      })

      // en creant le nouveau user on récupere l'id qui va
      // nous permettre de génerer ls tokens
      const tokens = await this.getTokens(user.id, user.email, user.roles)
      

      // on crypte le refreshToken avant son insertion en base de données
      const hashedRefreshtoken = await argon2.hash(tokens.refreshToken)

      // on met à jour le nouveau user en enregistrant son 
      // refreshToken
      await this.prismaService.user.update({
        where: {
          id: user.id,
        },
        data: {
          refreshToken: hashedRefreshtoken,
        },
      })

      //envoi de l'email de confirmation
      let token =''
      if(param.mode && param.mode === 'mobile'){ // verif par code
        token= (Math.floor(100000 + Math.random() * 9000000)).toString()
      } else { // verif par lien
        token = (await argon2.hash(Buffer.from(Math.floor(100000 + Math.random() * 9000000).toString()).toString('base64'))).split('p=')[1].replaceAll('/', '')
      }
      

      // creation de l'entrée dans la table emailVerification
      try {
        await this.prismaService.emailVerification.create({
          data: {
            email: dto.email,
            emailToken: token,
            exp: new Date()
          }
        })

      } catch(e) {
        console.log('database error: ', e)
        throw new ForbiddenException('Database error')
      }

      // ******* ici nous appelons l'envoi du mail sans utiliser 
      // d'évènement:
      // await this.emailService.sendEmailConfirmation(dto.email, token)

      // ici nous appelons l'envoi en utilisant un évènement
      // nommé user.verify-email dont le type est défini
      // dans event-emitter/interfaces:
      this.eventEmitter.emit('user.verify-email', {
        email: dto.email,
        token: token,
        mode: param.mode
      })


      console.log(typeof this.token_mode)

      // envoi du token par cookie http-only
      if('true' === this.token_mode) {
        res.cookie('jwt', tokens.accessToken, {httpOnly: true, domain: this.frontendDomain,})
        return {refreshToken: tokens.refreshToken}
      }

      // sinon envoi par le corps de la réponse
      return tokens

    } catch(e) {
      if(e instanceof PrismaClientKnownRequestError) {
        console.log('error code: ', e.code)
        if(e.code === 'P2002') {
          throw new ForbiddenException('email already exists')
        }
      }
    }
  }

  async signin(
    dto: AuthDto,
    res: Response
  ): Promise<TokenDto> {
    // récupérer le user dans la db
    const user = await this.prismaService.user.findUnique({
      where: {
        email: dto.email,
      }
    })
    // si il existe pas lever une erreur
    if(!user) throw new ForbiddenException(
      'Email/mot de passe incorrects.'
    )

    // Si le compte est non actif, lever une erreur
    if(user.active !== '1') throw new ForbiddenException(
      'Compte désactivé.'
    )

    // Si l'email de l'utilisateur n'est pas vérifié
    if(user.verifiedEmail !== '1') throw new ForbiddenException(
      'Email non verifie'
    )

    // comparer le mot de passe
    const pwMatches = await argon2.verify(user.hash, dto.password)

    // si le password est incorrect lever une erreur
    if(!pwMatches) throw new ForbiddenException(
      'Email/mot de passe incorrects.'
    )
    // tout va bien, l'utilisateur est vérifié.
    // on génère les tokens:
    const tokens = await this.getTokens(user.id, user.email, user.roles)

    // on crypte le refreshToken avant de l'inserer dans la ligne de 
    // l'utilisateur en base de données
    const hashedRefreshtoken = await argon2.hash(tokens.refreshToken)

    // on met à jour le refreshToken de l'utilisateur en DB
    await this.prismaService.user.update({
      where: {
        id: user.id,
      },
      data: {
        refreshToken: hashedRefreshtoken,
      },
    })

    console.log(typeof this.token_mode)
    // envoi du token par cookie http-only
    if('true' === this.token_mode) {
      res.cookie('jwt', tokens.accessToken, {httpOnly: true, domain: this.frontendDomain,})
      return {refreshToken: tokens.refreshToken}
    }

    // sinon envoi par le corps de la réponse
    return tokens
  }

  async logout(userId: number): Promise<BasicResponse> {
    try{
      await this.prismaService.user.update({
        where: {
          id: userId,
        },
        data: {
          refreshToken: null,
        },
      })
    } catch(e) {
      throw new ForbiddenException('Logout failed!')
    }
    return {
      message: "Logout successfull"
    };
  }

  async getMe(jwtuser: any): Promise<MeDto> {
    // récupérer le user dans la db
    const user = await this.prismaService.user.findUnique({
      where: {
        id: jwtuser.sub,
        email: jwtuser.email
      }
    })
    // si il existe pas lever une erreur
    if(!user) throw new ForbiddenException('Invalid user')

    return {
      id: user.id,
      email: user.email,
      firstName: user.firstName,
      lastName: user.lastName,
      roles: user.roles,
      verified: user.verifiedEmail === '1',
      created_at: user.createdAt,
      updated_at: user.updatedAt
    }
  }

  async getTokens(userId: number, email: string, roles: Role[]): Promise<TokenDto> {
    const [accessToken, refreshToken] = await Promise.all([
      // on signe le token d'acces
      this.jwtService.signAsync(
        {
          sub: userId,
          email,
          roles,
        },
        {
          secret: this.config.get('JWT_ACCESS_SECRET'),
          expiresIn:'15m',
        }
      ),

      // on signe le refreshToken
      this.jwtService.signAsync(
        {
          sub: userId,
          email,
        },
        {
          secret: this.config.get('JWT_REFRESH_SECRET'),
          expiresIn:'1d',
        }
      ),

    ])
    
    let tokens: TokenDto = {
      accessToken,
      refreshToken,
    }
    return tokens
  }

  async refreshTokens(userId: number, refreshToken: string, res: Response): Promise<TokenDto> {

    const user = await this.prismaService.user.findUnique({
      where: {
        id: userId,
      },
    })

    // si on ne trouve pas le user ou s'il n'a pas de refreshToken
    if (!user?.refreshToken){
      throw new ForbiddenException('Access Denied');
    }

    // sinon on verifie la validité du refreshToken
    const refreshTokenMatches = await argon2.verify(
      user.refreshToken,
      refreshToken,
    );

    // Si ca ne match pas
    if (!refreshTokenMatches) throw new ForbiddenException('Access Denied');

    // Si ca match
    // on génère les tokens:
    const tokens: TokenDto = await this.getTokens(user.id, user.email, user.roles)

    // on crypte le refreshToken avant de l'inserer dans la ligne de 
    // l'utilisateur en base de données
    const hashedRefreshtoken = await argon2.hash(tokens.refreshToken)

    // on met à jour le refreshToken de l'utilisateur en DB
    await this.prismaService.user.update({
      where: {
        id: user.id,
      },
      data: {
        refreshToken: hashedRefreshtoken,
      },
    })

    console.log(typeof this.token_mode)
    // envoi du token par cookie http-only
    if('true' === this.token_mode) {
      res.cookie('jwt', tokens.accessToken, {httpOnly: true, domain: this.frontendDomain,})
      return {refreshToken: tokens.refreshToken}
    }

    // sinon envoi par le corps de la réponse
    return tokens
  }

  async verifyEmail(param:{email: string, token: string, mode?: string}): Promise<boolean>{
    const record = await this.prismaService.emailVerification.findFirst({
      where: {
        email: param.email,
        emailToken: param.token,
      },
    })

    if(!record) {
      return false
    }

    const emailValidity: ValidityInterface = this.config.get<ValidityInterface>('user.email-verification.validity')

    const tokenIsValid = this.tokenIsValid(record.exp.toString(), emailValidity)

    try{
      if(tokenIsValid) {
        const user = await this.prismaService.user.findUnique({
          where: {
            email: param.email
          }
        })

        if(!user) {
          return false
        }

        await this.prismaService.emailVerification.delete({
          where:{
            id: record.id,
          }
        })

        await this.prismaService.user.update({
          where: {
            id: user.id,
          },
          data: {
            verifiedEmail: "1"
          }
        })

      } else {
        return false
      }
    } catch(e) {
      return false
    }

    return true
  }

  async EmailAlreaddyVerified(email: string): Promise<boolean> {
    const user = await this.prismaService.user.findUnique({
      where: {
        email: email
      }
    })
    if(!user) {
      return false
    }

    if(user.verifiedEmail === "0"){
      return false
    }

    return true
  }

  async emailVerificationResend(body: EmailVerifDto): Promise<BasicResponse> {
    const user = await this.prismaService.user.findUnique({
      where: {
        email: body.email
      }
    })
    if(!user) {
      throw new ForbiddenException('Email invalid')
    }
    if(user.active !== "1") {
      throw new ForbiddenException('Account suspended')
    }
    if(user.verifiedEmail === "1") {
      throw new ForbiddenException('User already verified')
    }


    // envoi de l'email de confirmation
    // creation du token ou du code en fonction du mode
    let token =''
    if(body.mode && body.mode === 'mobile'){ // verif par code
      token= (Math.floor(100000 + Math.random() * 9000000)).toString()
    } else { // verif par lien
      token = (await argon2.hash(Buffer.from(Math.floor(100000 + Math.random() * 9000000).toString()).toString('base64'))).split('p=')[1].replaceAll('/', '')
    }
    
    // creation de l'entrée dans la table emailVerification
    try {
      const record = await this.prismaService.emailVerification.findFirst({
        where: {
          email: body.email,
        },
      })

      if(!record){
        await this.prismaService.emailVerification.create({
          data: {
            email: body.email,
            emailToken: token,
            exp: new Date()
          }
        })
      } else {
        await this.prismaService.emailVerification.update({
          where: {
            id: record.id
          },
          data: {
            email: body.email,
            emailToken: token,
            exp: new Date()
          }
        })
      }
      
    } catch(e) {
      console.log('database error: ', e)
      throw new ForbiddenException('Database error')
    }

    this.eventEmitter.emit('user.verify-email', {
      email: body.email,
      token: token,
      mode: body.mode
    })

    return {
        message: "email sent"
    };
  }

  async accountIsActive(email: string): Promise<boolean> {
    const user = await this.prismaService.user.findUnique({
      where: {
        email: email
      }
    })
    if(!user) {
      return false
    }

    if(user.active === "0"){
      return false
    }

    return true
  }

  getValidity(validity:ValidityInterface): number {
    return ((validity.days * 86400 ) + (validity.hours * 3600) + (validity.minutes * 60) + validity.seconds) * 1000  
  }

  tokenIsValid(startDate:string, validity:ValidityInterface) {
    const now = Date.now()
    return (now - Date.parse(startDate)) <= this.getValidity(validity)
  }

  async forgotPassSendEmail(param: EmailVerifDto): Promise<BasicResponse> {
    // récupérer le user dans la db
    const user = await this.prismaService.user.findUnique({
      where: {
        email: param.email,
      }
    })

    if(!user) {
      throw new ForbiddenException('Email invalid')
    }
    if(user.active !== "1") {
      throw new ForbiddenException('Account suspended')
    }

    // envoi de l'email de confirmation
    // creation du token ou du code en fonction du mode
    let token =''
    if(param.mode && param.mode === 'mobile'){ // verif par code
      token= (Math.floor(100000 + Math.random() * 9000000)).toString()
    } else { // verif par lien
      token = (await argon2.hash(Buffer.from(Math.floor(100000 + Math.random() * 9000000).toString()).toString('base64'))).split('p=')[1].replaceAll('/', '')
    }

    // mise à jour de l'utilisateur dans la table user:
    try {
      await this.prismaService.user.update({
        where: {
          id: user.id
        },
        data: {
          forgotPasswordToken: token,
          forgotPasswordExp: new Date()
        }
      })

    } catch(e) {
      console.log('database error: ', e)
      throw new ForbiddenException('Database error')
    }

    this.eventEmitter.emit('user.password-reset', {
      email: param.email,
      token: token,
      mode: param.mode
    })

    return {
        message: "email sent"
    };
  }

  async resetPassword(body: PasswordResetDto): Promise<BasicResponse> {

    const user = await this.prismaService.user.findUnique({
      where: {
        email: body.email,
        forgotPasswordToken: body.token,
      }
    })
    
    if(!user) {
      throw new ForbiddenException('Email/token invalid')
    }
    if(user.active !== "1") {
      throw new ForbiddenException('Account suspended')
    }

    // on verifie la validité du token
    const resetPassTokenValidity: ValidityInterface = this.config.get<ValidityInterface>('user.forgotten-pass.validity')

    const tokenIsValid = this.tokenIsValid(user.forgotPasswordExp.toString(), resetPassTokenValidity)

    if(!tokenIsValid) {
      throw new ForbiddenException('Token expired')
    }

    // generer le hash
    const hash = await argon2.hash(body.password)

    // on met le user à jour
    try {
      await this.prismaService.$transaction(async(tx) => {
        await tx.user.update({
          where: {
            id: user.id,
          },
          data: {
            hash: hash,
            forgotPasswordToken: null,
            forgotPasswordExp:null,
          }
        })
      })
    } catch(e) {
      console.log('database error: ', e)
      throw new ForbiddenException('Database error')
    }

    return {"message": "Password reset successful"}
  }

}