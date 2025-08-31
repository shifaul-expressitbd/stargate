 // src/swagger/swagger.service.ts
import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import type { INestApplication } from '@nestjs/common/interfaces';
import { ConfigService } from '@nestjs/config';
import { SwaggerModule } from '@nestjs/swagger';
import { createSwaggerConfig, SWAGGER_CONFIG } from './swagger.config';
import { UrlConfigService } from '../config/url.config';

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
    SWAGGER_CONFIG.tags.forEach((tag) => {
      documentBuilder.addTag(tag.name, tag.description);
    });
    const document = SwaggerModule.createDocument(
      this.app,
      documentBuilder.build(),
    );

    const baseUrl = this.urlConfigService?.getBaseUrl() || this.configService.get('FRONTEND_URL', 'http://localhost:5555');
    const swaggerDocsUrl = this.urlConfigService?.getSwaggerUrl() || `${baseUrl}/api/docs`;
    const googleClientId = this.configService.get('GOOGLE_CLIENT_ID');
    const githubClientId = this.configService.get('GITHUB_CLIENT_ID');

    SwaggerModule.setup('api/docs', this.app, document, {
      swaggerOptions: {
        persistAuthorization: true,
        tagsSorter: 'alpha',
        operationsSorter: 'alpha',
        security: [
          { 'JWT-auth': [] },
          { 'refresh-token': [] },
          // { 'impersonate-access-token': [] },
          // { 'impersonate-refresh-token': [] },
          { 'Google OAuth': ['openid', 'email', 'profile'] },
          { 'Facebook OAuth': ['email', 'public_profile'] },
          { 'GitHub OAuth': ['user:email', 'read:user'] },
        ],
        oauth: {
          clientId: googleClientId,
          redirectUrl: this.urlConfigService?.getOAuthCallbackUrl('google') || `${baseUrl}/api/auth/google/callback`,
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
