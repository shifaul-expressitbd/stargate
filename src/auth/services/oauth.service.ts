import {
  BadRequestException,
  Injectable,
  Logger,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { google } from 'googleapis';
import { LoggerService } from 'src/utils/logger/logger.service';
import { PrismaService } from '../../database/prisma/prisma.service';
import { AuthCoreService } from './auth-core.service';

@Injectable()
export class OAuthService {
  private readonly logger = new Logger(OAuthService.name);

  constructor(
    private readonly configService: ConfigService,
    private readonly prisma: PrismaService,
    private readonly loggerService: LoggerService,
    private readonly authCoreService: AuthCoreService,
  ) {}

  async getGoogleOAuth2Client() {
    const clientId = this.configService.get<string>('GOOGLE_CLIENT_ID');
    const clientSecret = this.configService.get<string>('GOOGLE_CLIENT_SECRET');
    const callbackUrl = this.configService.get<string>('GOOGLE_CALLBACK_URL');

    if (!clientId || !clientSecret || !callbackUrl) {
      throw new UnauthorizedException('Google OAuth is not configured');
    }

    const oauth2Client = new google.auth.OAuth2(
      clientId,
      clientSecret,
      callbackUrl,
    );

    // Add GTM scopes
    oauth2Client.credentials = {
      scope:
        'https://www.googleapis.com/auth/tagmanager.readonly https://www.googleapis.com/auth/tagmanager.edit.containers https://www.googleapis.com/auth/tagmanager.manage.accounts',
    };

    return oauth2Client;
  }

  async getGoogleTokens(userId: string) {
    const provider = await this.prisma.authProvider.findUnique({
      where: {
        userId_provider: {
          userId,
          provider: 'GOOGLE',
        },
      },
    });

    if (!provider || !provider.accessToken) {
      throw new UnauthorizedException(
        'Google OAuth tokens not found. Please authenticate with Google first.',
      );
    }

    // Return only the access token since the auth module handles token refresh
    return {
      accessToken: provider.accessToken,
    };
  }

  async getUserProviders(userId: string): Promise<any[]> {
    return this.prisma.authProvider.findMany({
      where: { userId },
      select: {
        id: true,
        provider: true,
        email: true,
        isPrimary: true,
        linkedAt: true,
        lastUsedAt: true,
      },
      orderBy: { linkedAt: 'asc' },
    });
  }

  async unlinkProvider(userId: string, provider: string): Promise<void> {
    const providerEnum = this.mapStringToProviderEnum(provider);

    const providerRecord = await this.prisma.authProvider.findUnique({
      where: {
        userId_provider: {
          userId,
          provider: providerEnum,
        },
      },
    });

    if (!providerRecord) {
      throw new NotFoundException(
        `Provider ${provider} is not linked to this account`,
      );
    }

    // Don't allow unlinking if it's the only provider and user has no password
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      select: { password: true },
    });
    if (!user?.password) {
      const providerCount = await this.prisma.authProvider.count({
        where: { userId },
      });

      if (providerCount <= 1) {
        throw new BadRequestException(
          'Cannot unlink the only authentication provider without a password set. Please set a password first.',
        );
      }
    }

    await this.prisma.authProvider.delete({
      where: { id: providerRecord.id },
    });

    // If the unlinked provider was primary, set another one as primary
    if (providerRecord.isPrimary) {
      const remainingProvider = await this.prisma.authProvider.findFirst({
        where: { userId },
        orderBy: { linkedAt: 'asc' },
      });

      if (remainingProvider) {
        await this.authCoreService.setPrimaryProvider(
          userId,
          remainingProvider.provider,
        );
      }
    }
  }

  async setPrimaryProvider(userId: string, provider: string): Promise<void> {
    const providerEnum = this.mapStringToProviderEnum(provider);
    await this.authCoreService.setPrimaryProvider(userId, providerEnum);
  }

  async getOAuthConfig(provider: string): Promise<any> {
    const baseUrl =
      this.configService.get<string>('BASE_URL') || 'http://localhost:5555';

    switch (provider.toLowerCase()) {
      case 'google':
        return {
          clientId: this.configService.get('GOOGLE_CLIENT_ID'),
          callbackUrl: this.configService.get('GOOGLE_CALLBACK_URL'),
          authUrl: `${baseUrl}/api/auth/google`,
        };

      case 'google-gtm':
        return {
          clientId: this.configService.get('GOOGLE_GTM_CLIENT_ID'),
          callbackUrl: this.configService.get('GOOGLE_GTM_CALLBACK_URL'),
          authUrl: `${baseUrl}/api/auth/google-gtm`,
          scopes: [
            'https://www.googleapis.com/auth/tagmanager.readonly',
            'https://www.googleapis.com/auth/tagmanager.manage.accounts',
            'https://www.googleapis.com/auth/tagmanager.edit.containers',
            'https://www.googleapis.com/auth/tagmanager.edit.containerversions',
            'https://www.googleapis.com/auth/tagmanager.publish',
          ],
        };

      case 'facebook':
        return {
          appId: this.configService.get('FACEBOOK_APP_ID'),
          callbackUrl: this.configService.get('FACEBOOK_CALLBACK_URL'),
          authUrl: `${baseUrl}/api/auth/facebook`,
        };

      case 'github':
        return {
          clientId: this.configService.get('GITHUB_CLIENT_ID'),
          callbackUrl: this.configService.get('GITHUB_CALLBACK_URL'),
          authUrl: `${baseUrl}/api/auth/github`,
        };

      default:
        throw new BadRequestException(
          `Unsupported OAuth provider: ${provider}`,
        );
    }
  }

  async refreshOAuthToken(userId: string, provider: string): Promise<void> {
    try {
      const providerEnum = this.mapStringToProviderEnum(provider);

      const providerRecord = await this.prisma.authProvider.findUnique({
        where: {
          userId_provider: {
            userId,
            provider: providerEnum,
          },
        },
      });

      if (!providerRecord) {
        throw new NotFoundException(`Provider ${provider} not found for user`);
      }

      if (!providerRecord.refreshToken) {
        throw new BadRequestException(
          `No refresh token available for ${provider}`,
        );
      }

      // Refresh the token based on provider
      switch (provider.toLowerCase()) {
        case 'google':
          await this.refreshGoogleToken(providerRecord);
          break;
        default:
          throw new BadRequestException(
            `Token refresh not supported for ${provider}`,
          );
      }

      this.logger.log(
        `Successfully refreshed ${provider} token for user ${userId}`,
      );
    } catch (error) {
      this.logger.error(
        `Failed to refresh ${provider} token for user ${userId}:`,
        error.message,
      );
      throw error;
    }
  }

  private async refreshGoogleToken(providerRecord: any): Promise<void> {
    const oauth2Client = await this.getGoogleOAuth2Client();
    oauth2Client.setCredentials({
      refresh_token: providerRecord.refreshToken,
    });

    const { credentials } = await oauth2Client.refreshAccessToken();
    const newExpiresAt = new Date(
      Date.now() + (credentials.expiry_date || 3600000),
    );

    await this.prisma.authProvider.update({
      where: { id: providerRecord.id },
      data: {
        accessToken: credentials.access_token,
        refreshToken: credentials.refresh_token || providerRecord.refreshToken,
        tokenExpiresAt: newExpiresAt,
        lastUsedAt: new Date(),
      },
    });
  }

  async validateOAuthProvider(
    userId: string,
    provider: string,
  ): Promise<boolean> {
    const providerEnum = this.mapStringToProviderEnum(provider);

    const providerRecord = await this.prisma.authProvider.findUnique({
      where: {
        userId_provider: {
          userId,
          provider: providerEnum,
        },
      },
    });

    if (!providerRecord) {
      return false;
    }

    // Check if token is expired
    if (
      providerRecord.tokenExpiresAt &&
      providerRecord.tokenExpiresAt < new Date()
    ) {
      // Try to refresh the token
      try {
        await this.refreshOAuthToken(userId, provider);
        return true;
      } catch (error) {
        this.logger.warn(
          `Failed to refresh expired token for ${provider}:`,
          error.message,
        );
        return false;
      }
    }

    return true;
  }

  private mapStringToProviderEnum(provider: string): any {
    const providerMap: { [key: string]: any } = {
      google: 'GOOGLE',
      facebook: 'FACEBOOK',
      github: 'GITHUB',
      twitter: 'TWITTER',
      linkedin: 'LINKEDIN',
      microsoft: 'MICROSOFT',
      apple: 'APPLE',
    };

    const enumValue = providerMap[provider.toLowerCase()];
    if (!enumValue) {
      throw new Error(`Unsupported provider: ${provider}`);
    }

    return enumValue;
  }
}
