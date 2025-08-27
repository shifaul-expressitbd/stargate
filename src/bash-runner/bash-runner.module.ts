import { Module } from '@nestjs/common';
import { SgtmRegionModule } from '../sgtm-region/sgtm-region.module';
import { BashRunnerController } from './bash-runner.controller';
import { BashRunnerService } from './bash-runner.service';

@Module({
  imports: [SgtmRegionModule],
  controllers: [BashRunnerController],
  providers: [BashRunnerService],
  exports: [BashRunnerService],
})
export class BashRunnerModule {}
