import { AuthModule } from './auth/auth.module';
import { MiddlewareConsumer, Module, RequestMethod } from '@nestjs/common';
import { UserModule } from './user/user.module';
import { BookmarkModule } from './bookmark/bookmark.module';
import { PrismaModule } from './prisma/prisma.module';
import { ConfigModule } from '@nestjs/config';
import { CsrfModule } from './csrf/csrf.module';
import { ThrottlerModule } from '@nestjs/throttler';
import { LoggerService } from './logger/logger.service';
import { LoggerController } from './logger/logger.controller';
import { LoggerModule } from './logger/logger.module';
import { MongooseModule } from '@nestjs/mongoose';
import { AuthController } from './auth/auth.controller';
import { UserLoggerMiddleware } from './middlewares/userlogger/userLogger.middleware';
import { FunctionalUserLogger } from './middlewares/functional-userlogger/functionalUserLoger.middleware';
import { EmailModule } from './email/email.module';
import { EventEmitterModule } from '@nestjs/event-emitter';
import { TypedEventEmitterModule } from './event-emitter/typed-event-emitter.module';
import configuration from '../config/configuration';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      load: [configuration]
    }),
    ThrottlerModule.forRoot([
      {
        // 3 appels max en 1 sec.
        name: 'short',
        ttl: 1000,
        limit: 3,
      },
      {
        // 20 appels max en 10 sec.
        name: 'medium',
        ttl: 10000,
        limit: 20
      },
      {
        // 100 appels max en 60 sec.
        name: 'long',
        ttl: 60000,
        limit: 100
      }
    ]),
    AuthModule, 
    UserModule, 
    BookmarkModule, 
    PrismaModule,
    CsrfModule,
    MongooseModule.forRoot(process.env.MONGODB_URL, {dbName: process.env.MONGODB_NAME}),
    LoggerModule,
    EmailModule,
    EventEmitterModule.forRoot({}),
    TypedEventEmitterModule,
  ],
  controllers: [LoggerController],
  providers: [
    LoggerService,
    
  ],
})
export class AppModule {
  configure(consumer: MiddlewareConsumer) {
    consumer
      .apply(UserLoggerMiddleware)
      .exclude({ path: 'auth', method: RequestMethod.PUT })
      .forRoutes(
        // { path: 'auth/signup', method: RequestMethod.GET },

        // { path: 'auth/(.*)', method: RequestMethod.POST },

        // ou on peut l'appliquer sur toutes les routes
        // du controller:
        AuthController,

      )
    
    consumer
      .apply(FunctionalUserLogger)

      .forRoutes(
        { path: 'auth/signin', method: RequestMethod.POST }
      );
  }
}