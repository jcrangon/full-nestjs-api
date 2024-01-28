import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Request } from 'express';
import { ExtractJwt, JwtFromRequestFunction, Strategy } from 'passport-jwt';
import { Role } from '../enums/role.enum';


type JwtPayload = {
  sub: string;
  email: string;
  roles: Role[];
};


@Injectable()

export class AccessTokenStrategy extends PassportStrategy(Strategy, 'jwt') {

  constructor() {
    const token_mode = process.env.TOKEN_MODE_COOKIE

    let extractedJWT: JwtFromRequestFunction

    if('true' === token_mode){
      extractedJWT = ExtractJwt.fromExtractors([
        AccessTokenStrategy.extractCookieJWT,
      ])
    } else {
      extractedJWT = ExtractJwt.fromExtractors([
        ExtractJwt.fromAuthHeaderAsBearerToken(),
      ])
    }
    super({
      jwtFromRequest: extractedJWT,
      secretOrKey: process.env.JWT_ACCESS_SECRET,
    });
  }

  validate(payload: JwtPayload) {
    // console.log(payload)
    return payload;
  }

  private static extractCookieJWT(req: Request) {
    if (
      req.cookies && 'jwt' in req.cookies && req.cookies.jwt.length >0
    ) {
      console.log('JWT:', req.cookies.jwt)
      return req.cookies.jwt
    }
    return null
  }
}