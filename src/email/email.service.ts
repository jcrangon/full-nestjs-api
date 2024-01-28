import { MailerService } from '@nestjs-modules/mailer';
import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { OnEvent } from '@nestjs/event-emitter';
import { EventPayloads } from 'src/event-emitter/interfaces/event-types.interface';

@Injectable()
export class EmailService {
  constructor(
    private mailerService: MailerService,
    private configService: ConfigService
  ) {}

  @OnEvent('user.verify-email')
  async sendEmailConfirmation(data: EventPayloads['user.verify-email']) {
    const {email, token, mode } = data

    if(!mode || mode !== 'mobile') {
      const url = `${this.configService.get<string>('SITE_SCHEME')}${this.configService.get<string>('SITE_DOMAIN')}${this.configService.get<string>('SITE_PORT') ? ':' : ''}${this.configService.get<string>('SITE_PORT')}${this.configService.get<string>('EMAIL_VERIFICATION_URI')}${email}/${token}`;

      try{
        await this.mailerService.sendMail({
          to: email,
          subject: 'Confirm your Email',
          template: './emailVerification',
          context: {
            url,
          },
        });
      } catch(e) {
        console.log('sending EmailVerification ERROR', e)
      }

    } else {
      let code = token
      try{
        await this.mailerService.sendMail({
          to: email,
          subject: 'Confirm your Email with your Code',
          template: './emailVerificationMobile',
          context: {
            code,
          },
        });
      } catch(e) {
        console.log('sending EmailVerification ERROR', e)
      }
    }
  }

  @OnEvent('user.password-reset')
  async sendPasswordResetEmail(data: EventPayloads['user.password-reset']) {
    const {email, token, mode } = data

    if(!mode || mode !== 'mobile') {
      const url = `${this.configService.get<string>('FRONTEND_URL')}${this.configService.get<string>('FRONT_FORGOT_PASS_URI')}${email}/${token}`;

      try{
        await this.mailerService.sendMail({
          to: email,
          subject: 'Reset your Password',
          template: './emailPasswordReset',
          context: {
            url,
          },
        });
      } catch(e) {
        console.log('sending Email Verification ERROR', e)
      }

    } else {
      let code = token
      try{
        await this.mailerService.sendMail({
          to: email,
          subject: 'Reset your Password with your Code',
          template: './emailPasswordResetMobile',
          context: {
            code,
          },
        });
      } catch(e) {
        console.log('sending Password Reset Email ERROR', e)
      }
    }
  }
}
