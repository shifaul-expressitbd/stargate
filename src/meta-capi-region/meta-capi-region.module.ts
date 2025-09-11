import { Module } from '@nestjs/common';
import { RolesGuard } from '../common/guards/roles.guard';
import { DatabaseModule } from '../database/database.module';
import { MetaCapiRegionController } from './meta-capi-region.controller';
import { MetaCapiRegionService } from './meta-capi-region.service';

@Module({
  imports: [DatabaseModule],
  controllers: [MetaCapiRegionController],
  providers: [MetaCapiRegionService, RolesGuard],
  exports: [MetaCapiRegionService],
})
export class MetaCapiRegionModule {}
