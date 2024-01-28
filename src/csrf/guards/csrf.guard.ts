import { Injectable, CanActivate, ExecutionContext } from '@nestjs/common';
import { Request, Response } from 'express';
import { doubleCsrf } from 'csrf-csrf';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class CsrfGuard implements CanActivate {
  constructor(
    private config: ConfigService
  ){}

  private csrfProtection = doubleCsrf({
    getSecret: () => this.config.get('CSRF_SECRET'),
    cookieName: this.config.get('CSRF_COOKIE_NAME'),
  });

  

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const req = context.switchToHttp().getRequest<Request>()
    const res = context.switchToHttp().getResponse<Response>()

    // console.log(req)

    // Votre middleware express transformé en guard
    this.csrfProtection.doubleCsrfProtection(req, res, (error: any) => {

      if (error == this.csrfProtection.invalidCsrfTokenError) {
        res.status(403).json({
          error: 'csrf validation error'
        })
        throw new Error('Csrf guard activated!')
      }
    });

    return true; 
  }
}
