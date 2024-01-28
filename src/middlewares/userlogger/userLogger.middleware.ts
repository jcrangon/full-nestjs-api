import { Injectable, NestMiddleware } from '@nestjs/common';
import { Request, Response, NextFunction } from 'express';
import { LoggerService } from '../../logger/logger.service';


@Injectable()

export class UserLoggerMiddleware implements NestMiddleware {

  constructor(
    private logger: LoggerService
  ) {}
  
  use(req: Request, res: Response, next: NextFunction) {
    this.logger.log('REQUEST-cookies: ' + JSON.stringify(req['cookies']));
    this.logger.log('RESPONSE-cookies: ' + JSON.stringify(res['cookies']));
    next();
  }
}