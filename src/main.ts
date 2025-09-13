// src/main.ts
import { RequestMethod, ValidationPipe } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { NestFactory } from '@nestjs/core';
import cookieParser from 'cookie-parser';
import { AppModule } from './app.module';
import { HttpExceptionFilter } from './common/filters/http-exception.filter';
import { LoggingInterceptor } from './common/interceptors/logging.interceptor';
import { ResponseInterceptor } from './common/interceptors/response.interceptor';
import { CsrfMiddleware } from './common/middleware/csrf.middleware';
import { UrlConfigService } from './config/url.config';
import { SwaggerService } from './swagger/swagger.service';
import { LoggerService } from './utils/logger/logger.service';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  // Enable cookie parser (required for csrf-csrf)
  app.use(cookieParser());

  // Apply CSRF middleware
  const csrfMiddleware = app.get(CsrfMiddleware);
  app.use((req, res, next) => csrfMiddleware.use(req, res, next));

  // Set global prefix
  app.setGlobalPrefix('api', {
    exclude: [{ path: 'files*', method: RequestMethod.ALL }],
  });

  // Get config service
  const configService = app.get(ConfigService);

  // Global pipes
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
      transform: true,
      transformOptions: {
        enableImplicitConversion: true,
      },
    }),
  );

  // Global filters
  app.useGlobalFilters(new HttpExceptionFilter());

  // Global interceptors
  app.useGlobalInterceptors(
    new LoggingInterceptor(configService),
    new ResponseInterceptor(),
  );

  // CORS
  const urlConfigService = new UrlConfigService(configService);
  const corsOrigins = urlConfigService.getCorsOrigins();

  app.enableCors({
    origin: corsOrigins,
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'],
    allowedHeaders: [
      'Content-Type',
      'Authorization',
      'X-Requested-With',
      'X-API-Key',
    ],
  });

  // Create SwaggerService instance and initialize
  const swaggerService = new SwaggerService(configService, app);
  swaggerService.onModuleInit();

  const port = configService.get('port', 5555);
  await app.listen(port);

  const logger = app.get(LoggerService);
  logger.info(
    `🚀 Application is running on: http://localhost:${port}`,
    'Application',
  );
  logger.info(
    `🚀 Swagger is running on: http://localhost:${port}/api/docs`,
    'Application',
  );
}

bootstrap();
