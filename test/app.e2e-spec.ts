import { Test } from '@nestjs/testing';
import { AppModule } from '../src/app.module';
import { INestApplication, ValidationPipe, VersioningType } from '@nestjs/common';
import helmet from 'helmet';
import * as cookieParser from 'cookie-parser';
import { PrismaService } from '../src/prisma/prisma.service';
import * as pactum from 'pactum'
import { like } from 'pactum-matchers';
import { AuthDto } from 'src/auth/dto';
import { EmailVerifDto } from 'src/auth/dto/emailVerif.dto';
import { MeDto } from '../src/auth/dto/me.dto';

describe('App e2e', () => {

  let app: INestApplication
  let prisma: PrismaService

  beforeAll(async () => {
    
    const moduleRef = await Test.createTestingModule({
      imports: [AppModule],
    }).compile()

    app = moduleRef.createNestApplication()

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

    await app.init()
    await app.listen(3333)

    prisma = app.get(PrismaService)
    await prisma.cleanDb()
  })

  afterAll(() => {
    app.close()
  })

  // test Auth

  describe('Auth', () => {
    describe('Get Csrf', () => {
      it('should get Csrf', () => {
        return pactum
        .spec()
        .withHeaders('Content-Type', 'application/json')
        .get(
          'http://localhost:3333/api/v1/csrf-token/get'
        )
        .expectStatus(200)
        .expectJsonMatch({
          token: like('sdjkhfksldkjsmdflm')
        })
      })
    })

    describe('Signup', () => {
      it('Should signup', async () => {
        const dto: AuthDto = {
          email: 'testuser@email.com',
          password: '123456789'
        }
        // on récupère le cookie avec le jeton csrf crypté:
        const csrfCookie = await pactum
        .spec()
        .get('http://localhost:3333/api/v1/csrf-token/get')
        .expectJsonMatch({
          token: like('sdjkhfksldkjsmdflm')
        })
        .stores('CSRF', 'token')
        .returns((ctx) => {
          return ctx.res.headers['set-cookie'];
        });

        // on teste la route
        return pactum
        .spec()
        .withHeaders('Content-Type', 'application/json')
        .withHeaders('x-csrf-token', '$S{CSRF}')
        .withCookies(csrfCookie[0])
        .post(
          'http://localhost:3333/api/v1/auth/signup'
        )
        .withBody(dto)
        .expectStatus(201)

      })
    })

    describe('Email Verification', () => {
      const emailVerifDto: EmailVerifDto = {
        email: 'testuser@email.com',
      }
      it('should resend Verification email', () => {
        return pactum
        .spec()
        .withHeaders('Content-Type', 'application/json')
        .post(
          'http://localhost:3333/api/v1/auth/email-verification/resend'
        )
        .withBody(emailVerifDto)
        .expectStatus(201)
        .expectJsonMatch({
          message: "email sent"
        })
      })

      it('should verify User email', async () => {
        const userData = await prisma.emailVerification.findFirst({
          where: {
            email: 'testuser@email.com'
          },
        })
        const email = userData.email
        const token = userData.emailToken

        return pactum 
        .spec()
        .withHeaders('Content-Type', 'application/json')
        .get(
          `http://localhost:3333/api/v1/auth/confirm/${email}/${token}` 
        )
        .expectStatus(302)
      })
    })

    describe('Signin', () => {
      it('Should signin', async () => {
        const dto: AuthDto = {
          email: 'testuser@email.com',
          password: '123456789'
        }
        // on récupère le cookie avec le jeton csrf crypté:
        const csrfCookie = await pactum
        .spec()
        .get('http://localhost:3333/api/v1/csrf-token/get')
        .expectJsonMatch({
          token: like('sdjkhfksldkjsmdflm')
        })
        .stores('CSRF', 'token')
        .returns((ctx) => {
          return ctx.res.headers['set-cookie'];
        });

        // on teste la route
        return pactum
        .spec()
        .withHeaders('Content-Type', 'application/json')
        .withHeaders('x-csrf-token', '$S{CSRF}')
        .withCookies(csrfCookie[0])
        .post(
          'http://localhost:3333/api/v1/auth/signin'
        )
        .withBody(dto)
        .expectStatus(201)
        .expectJsonMatch({
          accessToken: like('ksdfhgkflgkjfmgdpfkodgjfo'),
          refreshToken: like('iuiudhfiughdofgdijgoidjfgo')
        })
        .stores('ACCESSTOKEN', 'accessToken')
        .stores('REFRESHTOKEN', 'refresToken')
      })
    })

    describe('Get Me', () => {
      it('Should getme', () => {
        return pactum
        .spec()
        .withHeaders('Content-Type', 'application/json')
        .withBearerToken('$S{ACCESSTOKEN}')
        .get(
          'http://localhost:3333/api/v1/auth/me'
        )
        .expectStatus(200)
        .expectJsonSchema({
          "type": "object"
        })
      })
    })

  })


})