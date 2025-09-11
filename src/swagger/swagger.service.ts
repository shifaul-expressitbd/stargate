// src/swagger/swagger.service.ts
import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import type { INestApplication } from '@nestjs/common/interfaces';
import { ConfigService } from '@nestjs/config';
import { SwaggerModule } from '@nestjs/swagger';
import { UrlConfigService } from '../config/url.config';
import { createSwaggerConfig, SWAGGER_CONFIG } from './swagger.config';

@Injectable()
export class SwaggerService implements OnModuleInit {
  private readonly logger = new Logger(SwaggerService.name);

  constructor(
    private readonly configService: ConfigService,
    private readonly app: INestApplication,
    private readonly urlConfigService?: UrlConfigService,
  ) {}

  onModuleInit(): void {
    if (this.configService.get('NODE_ENV') !== 'production') {
      this.setupSwagger();
    }
  }

  private setupSwagger(): void {
    const documentBuilder = createSwaggerConfig();

    // Add tags in the exact order specified
    SWAGGER_CONFIG.tags.forEach((tag) => {
      documentBuilder.addTag(tag.name, tag.description);
    });

    const document = SwaggerModule.createDocument(
      this.app,
      documentBuilder.build(),
    );

    // Add tag groups to force ordering in Swagger UI
    if (SWAGGER_CONFIG['x-tagGroups']) {
      document['x-tagGroups'] = SWAGGER_CONFIG['x-tagGroups'];
    }

    const baseUrl =
      this.urlConfigService?.getBaseUrl() ||
      this.configService.get('FRONTEND_URL', 'http://localhost:5555');
    const swaggerDocsUrl =
      this.urlConfigService?.getSwaggerUrl() || `${baseUrl}/api/docs`;
    const googleClientId = this.configService.get('GOOGLE_CLIENT_ID');
    const githubClientId = this.configService.get('GITHUB_CLIENT_ID');

    // Create the exact tag order array for the custom sorter
    const tagOrder = SWAGGER_CONFIG.tags.map((tag) => tag.name);

    SwaggerModule.setup('api/docs', this.app, document, {
      swaggerOptions: {
        persistAuthorization: true,
        tagsSorter: (a: string, b: string) => {
          // Define tagOrder inline since it can't be accessed from outside
          const tagOrder = [
            'Application',
            'Authentication',
            'OAuth Authentication',
            'Two-Factor Authentication',
            'Session Management',
            'Users',
            'Impersonation',
            'sGTM-Regions',
            'sGTM-Containers',
            'Google Tag Manager',
            'mCAPI-Regions',
            'mCAPI-Containers',
          ];

          const indexA = tagOrder.indexOf(a);
          const indexB = tagOrder.indexOf(b);

          // If both tags are in our ordered list, sort by the predefined order
          if (indexA !== -1 && indexB !== -1) {
            return indexA - indexB;
          }

          // If only one tag is in our ordered list, it comes first
          if (indexA !== -1) return -1;
          if (indexB !== -1) return 1;

          // If neither tag is in our ordered list, sort alphabetically
          return a.localeCompare(b);
        },
        operationsSorter: 'alpha',
        security: [
          { 'JWT-auth': [] },
          { 'refresh-token': [] },
          { 'Google OAuth': ['openid', 'email', 'profile'] },
          { 'Facebook OAuth': ['email', 'public_profile'] },
          { 'GitHub OAuth': ['user:email', 'read:user'] },
        ],
        oauth: {
          clientId: googleClientId,
          redirectUrl:
            this.urlConfigService?.getOAuthCallbackUrl('google') ||
            `${baseUrl}/api/auth/google/callback`,
          usePkceWithAuthorizationCodeGrant: true,
          scopes: ['openid', 'email', 'profile'],
        },
        oauth2RedirectUrl: `${swaggerDocsUrl}/oauth2-redirect.html`,
        initOAuth: {
          clientId: githubClientId || googleClientId,
          usePkceWithAuthorizationCodeGrant: true,
        },
      },
      customSiteTitle: SWAGGER_CONFIG.title,
    });

    this.logger.log('✅ Swagger is available at /api/docs');
  }
}
