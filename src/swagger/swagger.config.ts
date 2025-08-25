// src/swagger/swagger.config.ts
import { DocumentBuilder } from '@nestjs/swagger';

export const SWAGGER_CONFIG = {
  title: 'StarGate NestJS API',
  description:
    'A robust backend API with authentication, command execution, and real-time updates',
  version: '1.0.0',
  tags: [
    {
      name: 'Authentication',
      description: 'User authentication and authorization',
    },
    { name: 'Users', description: 'User management' },
    { name: 'Impersonation', description: 'User impersonation management' },
  ],
};

export function createSwaggerConfig() {
  const config = new DocumentBuilder()
    .setTitle(SWAGGER_CONFIG.title)
    .setDescription(SWAGGER_CONFIG.description)
    .setVersion(SWAGGER_CONFIG.version)

    // ✅ Main JWT Auth (for access tokens)
    .addBearerAuth(
      {
        type: 'http',
        scheme: 'bearer',
        bearerFormat: 'JWT',
        description: 'Enter your **access token**',
      },
      'JWT-auth',
    )

    // ✅ Refresh Token Scheme (critical for /refresh)
    .addBearerAuth(
      {
        type: 'http',
        scheme: 'bearer',
        bearerFormat: 'JWT',
        description: 'Enter your **refresh token**',
      },
      'refresh-token',
    )

    // ✅ Impersonation Access Token Scheme
    // .addBearerAuth(
    //   {
    //     type: 'http',
    //     scheme: 'bearer',
    //     bearerFormat: 'JWT',
    //     description: 'Enter impersonation **access token**',
    //   },
    //   'impersonate-access-token',
    // )

    // ✅ Impersonation Refresh Token Scheme
    // .addBearerAuth(
    //   {
    //     type: 'http',
    //     scheme: 'bearer',
    //     bearerFormat: 'JWT',
    //     description: 'Enter impersonation **refresh token**',
    //   },
    //   'impersonate-refresh-token',
    // )

    // ✅ Google OAuth
    .addOAuth2(
      {
        type: 'oauth2',
        description: 'Google OAuth 2.0',
        flows: {
          authorizationCode: {
            authorizationUrl: 'https://accounts.google.com/o/oauth2/v2/auth',
            tokenUrl: 'https://oauth2.googleapis.com/token',
            scopes: {
              openid: 'OpenID Connect',
              email: 'View your email address',
              profile: 'View your basic profile info',
            },
          },
        },
      },
      'Google OAuth',
    )
    // ✅ Facebook OAuth
    .addOAuth2(
      {
        type: 'oauth2',
        description: 'Facebook OAuth 2.0',
        flows: {
          authorizationCode: {
            authorizationUrl: 'https://www.facebook.com/v12.0/dialog/oauth',
            tokenUrl: 'https://graph.facebook.com/v12.0/oauth/access_token',
            scopes: {
              email: 'View your email address',
              public_profile: 'View your basic profile info',
            },
          },
        },
      },
      'Facebook OAuth',
    )

    // ✅ GitHub OAuth
    .addOAuth2(
      {
        type: 'oauth2',
        description: 'GitHub OAuth 2.0',
        flows: {
          authorizationCode: {
            authorizationUrl: 'https://github.com/login/oauth/authorize',
            tokenUrl: 'https://github.com/login/oauth/access_token',
            scopes: {
              'user:email': 'View your email address',
              'read:user': 'View your basic profile info',
            },
          },
        },
      },
      'GitHub OAuth',
    );

  return config;
}
