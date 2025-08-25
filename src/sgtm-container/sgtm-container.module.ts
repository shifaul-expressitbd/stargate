import { Module } from '@nestjs/common';
import { DatabaseModule } from 'src/database/database.module';
import { BashRunnerModule } from '../bash-runner/bash-runner.module';
import { SgtmContainerController } from './sgtm-container.controller';
import { SgtmContainerService } from './sgtm-container.service';

@Module({
  imports: [DatabaseModule, BashRunnerModule],
  providers: [SgtmContainerService],
  controllers: [SgtmContainerController],
})
export class SgtmContainerModule {}
