import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { doubleCsrf } from 'csrf-csrf';
import { Request, Response } from 'express';

@Injectable()
export class CsrfService  {
  constructor(
    private config: ConfigService
  ){}

  private csrfProtection = doubleCsrf({
    getSecret: () => this.config.get('CSRF_SECRET'),
    cookieName: this.config.get('CSRF_COOKIE_NAME'),
  });

  getToken(req: Request, res: Response) {
    // return res.json({
    //   token: this.csrfProtection.generateToken(req, res)
    // });
    // avec res({passthough: true})on peut continuer
    // a utiliser le framework sans dévier vers Express:
    const csrf = {
      token: this.csrfProtection.generateToken(req, res)
    }
    return csrf
  }
}