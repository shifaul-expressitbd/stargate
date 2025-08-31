import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PassportStrategy } from '@nestjs/passport';
import { Profile, Strategy } from 'passport-google-oauth20';
import { AuthService } from '../auth.service';
import { UrlConfigService } from '../../config/url.config';

@Injectable()
export class GoogleGtmStrategy extends PassportStrategy(
  Strategy,
  'google-gtm',
) {
  private readonly logger = new Logger(GoogleGtmStrategy.name);

  constructor(
    private readonly configService: ConfigService,
    private readonly authService: AuthService,
    private readonly urlConfigService: UrlConfigService,
  ) {
    const clientId = configService.get<string>('GOOGLE_GTM_CLIENT_ID');
    const clientSecret = configService.get<string>('GOOGLE_GTM_CLIENT_SECRET');

    // Validate required configuration
    if (!clientId || !clientSecret) {
      const missingVars: string[] = [];
      if (!clientId) missingVars.push('GOOGLE_GTM_CLIENT_ID');
      if (!clientSecret) missingVars.push('GOOGLE_GTM_CLIENT_SECRET');

      throw new Error(
        `Missing required Google OAuth configuration: ${missingVars.join(', ')}. ` +
          'Please check your .env file and ensure these variables are set.',
      );
    }

    const callbackURL = urlConfigService.getOAuthCallbackUrl('google-gtm');

    super({
      clientID: clientId,
      clientSecret: clientSecret,
      callbackURL,
      scope: [
        'email',
        'profile',
        'openid',
        'https://www.googleapis.com/auth/tagmanager.readonly',
        'https://www.googleapis.com/auth/tagmanager.manage.accounts',
        'https://www.googleapis.com/auth/tagmanager.edit.containers',
        'https://www.googleapis.com/auth/tagmanager.edit.containerversions',
        'https://www.googleapis.com/auth/tagmanager.publish',
      ],
      accessType: 'offline', // Request refresh token
      prompt: 'consent', // Force consent screen to ensure we get a refresh token
      passReqToCallback: false,
    });

    // Log configuration values (without sensitive data) for debugging
    console.log('Google GTM OAuth Config:', {
      clientId: clientId ? `${clientId.substring(0, 10)}...` : 'NOT SET',
      clientSecret: clientSecret ? 'SET' : 'NOT SET',
      callbackURL,
    });

    this.logger.log('Google GTM OAuth strategy initialized successfully');
  }

  async validate(
    accessToken: string,
    refreshToken: string,
    profile: Profile,
  ): Promise<any> {
    try {
      const { name, emails, photos } = profile;

      if (!emails || emails.length === 0) {
        throw new Error('No email found in Google profile');
      }

      const user = {
        email: emails[0].value,
        name:
          `${name?.givenName || ''} ${name?.familyName || ''}`.trim() ||
          'Google User',
        avatar: photos?.[0]?.value || null,
        provider: 'google', // Use 'google' as the provider, same as regular Google OAuth
        providerId: profile.id,
        accessToken,
        refreshToken,
        providerData: {
          profile,
          raw: profile._raw,
          gtmScopes: true, // Mark this as having GTM permissions
        },
      };

      this.logger.log(`Google GTM OAuth validation for user: ${user.email}`);
      return this.authService.validateOAuthUser(user);
    } catch (error) {
      this.logger.error('Google GTM OAuth validation failed:', error.message);
      throw error;
    }
  }
}
