import { Module } from '@nestjs/common';
import { SgtmContainerService } from './sgtm-container.service';
import { SgtmContainerController } from './sgtm-container.controller';
import { HttpModule } from '@nestjs/axios';
import { DatabaseModule } from 'src/database/database.module';

@Module({
  imports: [DatabaseModule, HttpModule],
  providers: [SgtmContainerService],
  controllers: [SgtmContainerController],
})
export class SgtmContainerModule {}
