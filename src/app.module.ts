import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { APP_GUARD, APP_INTERCEPTOR } from '@nestjs/core';
import { EventEmitterModule } from '@nestjs/event-emitter';
import { ScheduleModule } from '@nestjs/schedule';
import { ThrottlerGuard, ThrottlerModule } from '@nestjs/throttler';
import { AdminModule } from './admin/admin.module';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { AuthModule } from './auth/auth.module';
import { ImpersonationGuard } from './common/guards/impersonation.guard';
import { JwtAuthGuard } from './common/guards/jwt-auth.guard';
import { RolesGuard } from './common/guards/roles.guard';
import { ResponseInterceptor } from './common/interceptors/response.interceptor';
import { CsrfMiddleware } from './common/middleware/csrf.middleware';
import { UrlConfigService } from './config/url.config';
import { validationSchema } from './config/validation.schema';
import { DatabaseModule } from './database/database.module';
import { FileModule } from './file/file.module';
import { GoogleTagManagerModule } from './google-tag-manager/google-tag-manager.module';
import { MailModule } from './mail/mail.module';
import { MetaCapiContainerModule } from './meta-capi-container/meta-capi-container.module';
import { MetaCapiRegionModule } from './meta-capi-region/meta-capi-region.module';
import { SgtmContainerModule } from './sgtm-container/sgtm-container.module';
import { SgtmRegionModule } from './sgtm-region/sgtm-region.module';
import { SupportTicketsModule } from './support-tickets/support-tickets.module';
import { UsersModule } from './users/users.module';
import { LoggerService } from './utils/logger/logger.service';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      load: [() => require('./config/app.config').appConfig()],
      validationSchema,
      envFilePath: ['.env.local', '.env'],
    }),
    ScheduleModule.forRoot(),
    {
      module: class { },
      providers: [UrlConfigService],
      exports: [UrlConfigService],
      global: true,
    },
    // FIX: Corrected ThrottlerModule configuration - must use 'throttlers' array
    ThrottlerModule.forRootAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: (config: ConfigService) => ({
        throttlers: [
          {
            ttl: config.get<number>('THROTTLE_TTL', 60000),
            limit: config.get<number>('THROTTLE_LIMIT', 100),
          },
        ],
      }),
    }),
    EventEmitterModule.forRoot({
      wildcard: false,
      delimiter: '.',
      newListener: false,
      removeListener: false,
      maxListeners: 10,
      verboseMemoryLeak: false,
      ignoreErrors: false,
    }),
    DatabaseModule,
    AuthModule,
    UsersModule,
    SgtmContainerModule,
    SgtmRegionModule,
    MetaCapiContainerModule,
    MetaCapiRegionModule,
    GoogleTagManagerModule,
    MailModule,
    AdminModule,
    SupportTicketsModule,
    FileModule,
  ],
  controllers: [AppController],
  providers: [
    AppService,
    LoggerService,
    {
      provide: APP_INTERCEPTOR,
      useClass: ResponseInterceptor,
    },
    {
      provide: APP_GUARD,
      useClass: JwtAuthGuard,
    },
    {
      provide: APP_GUARD,
      useClass: RolesGuard,
    },
    {
      provide: APP_GUARD,
      useClass: ThrottlerGuard,
    },
    ImpersonationGuard,
    CsrfMiddleware,
  ],
})
export class AppModule { }
