// src/swagger/swagger.module.ts
import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import type { INestApplication } from '@nestjs/common/interfaces';
import { ConfigService } from '@nestjs/config';
import { SwaggerModule as NestSwaggerModule } from '@nestjs/swagger';
import { createSwaggerConfig, SWAGGER_CONFIG } from './swagger.config';

@Injectable()
export class SwaggerService implements OnModuleInit {
  private readonly logger = new Logger(SwaggerService.name);

  constructor(
    private readonly configService: ConfigService,
    private readonly app: INestApplication,
  ) {}

  onModuleInit() {
    if (this.configService.get('NODE_ENV') === 'development') {
      this.setupSwagger();
    }
  }

  private setupSwagger() {
    const config = createSwaggerConfig();
    
    SWAGGER_CONFIG.tags.forEach(tag => {
      config.addTag(tag.name, tag.description);
    });

    const document = NestSwaggerModule.createDocument(this.app, config.build());
    NestSwaggerModule.setup('api/docs', this.app, document, {
      swaggerOptions: {
        persistAuthorization: true,
        tagsSorter: 'alpha',
        operationsSorter: 'alpha',
        security: [{ 'JWT-auth': [] }]
      },
    });

    this.logger.log('Swagger documentation available at /api/docs');
  }
}