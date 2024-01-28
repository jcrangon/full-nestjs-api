import { createParamDecorator, ExecutionContext, ForbiddenException } from '@nestjs/common';
import { PrismaService } from '../../prisma/prisma.service';
import { ConfigService } from '@nestjs/config';

export const Getme = createParamDecorator(
  async (data: unknown, ctx: ExecutionContext) => {
    const config = new ConfigService
    const prismaService = new PrismaService(config)
    const request: Express.Request = ctx.switchToHttp().getRequest();
    const user = await prismaService.user.findUnique({
      where: {
        id: request.user['sub'],
        email: request.user['email']
      }
    })

    if(!user) throw new ForbiddenException('Invalid credentials')
    
    return {
      id: user.id,
      email: user.email,
      firstName: user.firstName,
      lastName: user.lastName,
      roles: user.roles,
      verified: user.verifiedEmail === '1' ? true : false,
      created_at: user.createdAt,
      updated_at: user.updatedAt
    }
  },
);