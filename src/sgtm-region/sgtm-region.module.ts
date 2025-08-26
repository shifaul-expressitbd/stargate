import { Module } from '@nestjs/common';
import { RolesGuard } from '../common/guards/roles.guard';
import { DatabaseModule } from '../database/database.module';
import { SgtmRegionController } from './sgtm-region.controller';
import { SgtmRegionService } from './sgtm-region.service';

@Module({
  imports: [DatabaseModule],
  controllers: [SgtmRegionController],
  providers: [SgtmRegionService, RolesGuard],
  exports: [SgtmRegionService],
})
export class SgtmRegionModule {}
