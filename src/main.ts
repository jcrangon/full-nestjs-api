import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ValidationPipe, VersioningType } from '@nestjs/common';
import * as cookieParser from 'cookie-parser';
import helmet from 'helmet';
import { SwaggerModule, DocumentBuilder } from '@nestjs/swagger';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  app.use(helmet());
  app.setGlobalPrefix('api');
  
  app.enableVersioning({
    type: VersioningType.URI,
  });

  app.use(cookieParser(process.env.COOKIES_SECRET));
  app.useGlobalPipes(new ValidationPipe({
    whitelist: true
  }))
  app.enableCors({
    // allowedHeaders: ['content-type'],
    credentials: true,
    origin: process.env.FRONTEND_URL,
  })

  const config = new DocumentBuilder()
    .setTitle('NestJs Full Api')
    .setDescription('A NestJs backend example')
    .setVersion('1.0')
    // .addTag('Routes')
    .addBearerAuth()
    .build();
  const document = SwaggerModule.createDocument(app, config);
  SwaggerModule.setup('', app, document);

  await app.listen(3333);
}
bootstrap(); 
