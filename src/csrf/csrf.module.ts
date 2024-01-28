import { Global, Module } from '@nestjs/common';
import { CsrfService } from './csrf.service';
import { CsrfController } from './csrf.controller';

@Global()
@Module({
  controllers: [CsrfController],
  providers: [CsrfService],
  exports: [CsrfService]
})
export class CsrfModule {}
