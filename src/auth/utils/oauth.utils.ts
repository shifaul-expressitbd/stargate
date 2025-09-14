import { Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';

export class OAuthUtils {
  private static readonly logger = new Logger(OAuthUtils.name);

  /**
   * Get OAuth configuration for a specific provider
   */
  static getOAuthConfig(provider: string, configService: ConfigService): any {
    const baseUrl =
      configService.get<string>('BACKEND_URL') || 'http://localhost:5555';

    const configs = {
      google: {
        clientId: configService.get('GOOGLE_CLIENT_ID'),
        callbackUrl: `${baseUrl}/api/auth/google/callback`,
        authUrl: `${baseUrl}/api/auth/google`,
        scopes: ['email', 'profile', 'openid'],
      },
      'google-gtm': {
        clientId: configService.get('GOOGLE_GTM_CLIENT_ID'),
        callbackUrl: `${baseUrl}/api/auth/google-gtm/callback`,
        authUrl: `${baseUrl}/api/auth/google-gtm`,
        scopes: [
          'https://www.googleapis.com/auth/tagmanager.readonly',
          'https://www.googleapis.com/auth/tagmanager.manage.accounts',
          'https://www.googleapis.com/auth/tagmanager.edit.containers',
          'https://www.googleapis.com/auth/tagmanager.edit.containerversions',
          'https://www.googleapis.com/auth/tagmanager.publish',
        ],
      },
      facebook: {
        appId: configService.get('FACEBOOK_APP_ID'),
        callbackUrl: `${baseUrl}/api/auth/facebook/callback`,
        authUrl: `${baseUrl}/api/auth/facebook`,
      },
      github: {
        clientId: configService.get('GITHUB_CLIENT_ID'),
        callbackUrl: `${baseUrl}/api/auth/github/callback`,
        authUrl: `${baseUrl}/api/auth/github`,
      },
    };

    const config = configs[provider.toLowerCase()];
    if (!config) {
      throw new Error(
        `OAuth configuration not found for provider: ${provider}`,
      );
    }

    return config;
  }

  /**
   * Validate OAuth configuration
   */
  static validateOAuthConfig(
    provider: string,
    configService: ConfigService,
  ): void {
    const configs = {
      google: ['GOOGLE_CLIENT_ID', 'GOOGLE_CLIENT_SECRET'],
      'google-gtm': ['GOOGLE_GTM_CLIENT_ID', 'GOOGLE_GTM_CLIENT_SECRET'],
      facebook: ['FACEBOOK_APP_ID', 'FACEBOOK_APP_SECRET'],
      github: ['GITHUB_CLIENT_ID', 'GITHUB_CLIENT_SECRET'],
    };

    const requiredEnvVars = configs[provider.toLowerCase()];
    if (!requiredEnvVars) {
      throw new Error(`Unsupported OAuth provider: ${provider}`);
    }

    const missingVars = requiredEnvVars.filter(
      (envVar) => !configService.get(envVar),
    );

    if (missingVars.length > 0) {
      this.logger.error(
        `Missing OAuth configuration for ${provider}: ${missingVars.join(', ')}`,
      );
      throw new Error(
        `OAuth configuration incomplete for provider: ${provider}`,
      );
    }
  }

  /**
   * Generate OAuth authorization URL for GitHub
   */
  static generateGitHubAuthUrl(
    clientId: string,
    callbackUrl: string,
    scope = 'user:email',
  ): string {
    return `https://github.com/login/oauth/authorize?client_id=${clientId}&redirect_uri=${encodeURIComponent(
      callbackUrl,
    )}&scope=${encodeURIComponent(scope)}`;
  }
}
