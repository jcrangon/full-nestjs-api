import { Request, Response, NextFunction } from 'express';
import { LoggerService } from '../../logger/logger.service';


export function FunctionalUserLogger(req: Request, res: Response, next: NextFunction) {
  
  const logger = new LoggerService

  logger.log('FUNCTIONAL MID - REQUEST-cookies: ' + JSON.stringify(req['cookies']));

  logger.log('FUNCTIONAL MID - RESPONSE-cookies: ' + JSON.stringify(res['cookies']));

  next();

}