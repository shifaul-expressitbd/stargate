import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { AuthModule } from '../auth/auth.module';
import { GoogleTagManagerController } from './google-tag-manager.controller';
import { GoogleTagManagerService } from './google-tag-manager.service';

@Module({
  imports: [ConfigModule, AuthModule],
  controllers: [GoogleTagManagerController],
  providers: [GoogleTagManagerService],
  exports: [GoogleTagManagerService],
})
export class GoogleTagManagerModule {}
