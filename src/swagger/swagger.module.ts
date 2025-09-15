// src/swagger/swagger.module.ts
import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import type { INestApplication } from '@nestjs/common/interfaces';
import { ConfigService } from '@nestjs/config';
import { SwaggerModule as NestSwaggerModule } from '@nestjs/swagger';
import { UrlConfigService } from 'src/config/url.config';
import { createSwaggerConfig, SWAGGER_CONFIG } from './swagger.config';

@Injectable()
export class SwaggerService implements OnModuleInit {
  private readonly logger = new Logger(SwaggerService.name);

  constructor(
    private readonly configService: ConfigService,
    private readonly app: INestApplication,
    private readonly urlConfigService?: UrlConfigService,
  ) {}

  onModuleInit() {
    const swaggerEnabled = this.configService.get<string>(
      'SWAGGER_ENABLED',
      'false',
    );
    if (swaggerEnabled === 'true') {
      this.setupSwagger();
    }
  }

  private setupSwagger() {
    const baseUrl =
      this.urlConfigService?.getBaseUrl() || 'http://localhost:5555';
    const config = createSwaggerConfig(baseUrl);

    SWAGGER_CONFIG.tags.forEach((tag) => {
      config.addTag(tag.name, tag.description);
    });

    const document = NestSwaggerModule.createDocument(this.app, config.build());

    // Add tag groups to force ordering in Swagger UI
    if (SWAGGER_CONFIG['x-tagGroups']) {
      document['x-tagGroups'] = SWAGGER_CONFIG['x-tagGroups'];
    }

    // Custom tag sorter that respects the order in SWAGGER_CONFIG.tags
    const tagOrder = SWAGGER_CONFIG.tags.map((tag) => tag.name);

    NestSwaggerModule.setup('api/docs', this.app, document, {
      swaggerOptions: {
        persistAuthorization: true,
        tagsSorter: (a: string, b: string) => {
          const indexA = tagOrder.indexOf(a);
          const indexB = tagOrder.indexOf(b);
          if (indexA === -1) return 1; // Unknown tags go to the end
          if (indexB === -1) return -1;
          return indexA - indexB;
        },
        operationsSorter: 'alpha',
        security: [{ 'JWT-auth': [] }],
      },
    });

    this.logger.log('Swagger documentation available at /api/docs');
  }
}
