import { HttpModule } from '@nestjs/axios';
import { Module } from '@nestjs/common';
import { DatabaseModule } from '../database/database.module';
import { SgtmRegionModule } from '../sgtm-region/sgtm-region.module';
import { SgtmContainerController } from './sgtm-container.controller';
import { SgtmContainerService } from './sgtm-container.service';

@Module({
  imports: [DatabaseModule, HttpModule, SgtmRegionModule],
  providers: [SgtmContainerService],
  controllers: [SgtmContainerController],
})
export class SgtmContainerModule {}
