import { Controller, Get } from '@nestjs/common';
import { LoggerService } from './logger.service';
import { ApiTags } from '@nestjs/swagger';

@ApiTags('Logger')
@Controller('logger')
export class LoggerController {
  constructor(private readonly logger: LoggerService) {}

  @Get('info')
  getInfoLog() {
    this.logger.log(
      'This is an INFO log message from the LoggerController.',
      'LoggerController',
    );
    return 'Logged an INFO message.';
  }

  @Get('error')
  getErrorLog() {
    this.logger.error(
      'This is an ERROR log message from the LoggerController.',
      null,
      'LoggerController',
    );
    return 'Logged an ERROR message.';
  }

  @Get('warn')
  getWarnLog() {
    this.logger.warn(
      'This is a WARN log message from the LoggerController.',
      'LoggerController',
    );
    return 'Logged a WARN message.';
  }

  @Get('debug')
  getDebugLog() {
    this.logger.debug(
      'This is a DEBUG log message from the LoggerController.',
      'LoggerController',
    );
    return 'Logged a DEBUG message.';
  }
}
