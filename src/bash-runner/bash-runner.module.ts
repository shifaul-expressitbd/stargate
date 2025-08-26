import { Module } from '@nestjs/common';
import { SgtmRegionModule } from '../sgtm-region/sgtm-region.module';
import { BashRunnerService } from './bash-runner.service';

@Module({
  imports: [SgtmRegionModule],
  providers: [BashRunnerService],
  exports: [BashRunnerService],
})
export class BashRunnerModule {}
