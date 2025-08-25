import { Module } from '@nestjs/common';
import { BashRunnerService } from './bash-runner.service';

@Module({
  providers: [BashRunnerService],
  exports: [BashRunnerService],
})
export class BashRunnerModule {}
