import { HttpModule } from '@nestjs/axios';
import { Module } from '@nestjs/common';
import { DatabaseModule } from '../database/database.module';
import { MetaCapiContainerController } from './meta-capi-container.controller';
import { MetaCapiContainerService } from './meta-capi-container.service';

@Module({
  imports: [DatabaseModule, HttpModule],
  providers: [MetaCapiContainerService],
  controllers: [MetaCapiContainerController],
})
export class MetaCapiContainerModule {}
