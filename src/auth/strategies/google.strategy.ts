// src/auth/strategies/google.strategy.ts
import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PassportStrategy } from '@nestjs/passport';
import { Profile, Strategy } from 'passport-google-oauth20';
import { UrlConfigService } from '../../config/url.config';
import { AuthService } from '../auth.service';

@Injectable()
export class GoogleStrategy extends PassportStrategy(Strategy, 'google') {
  private readonly logger = new Logger(GoogleStrategy.name);

  constructor(
    private readonly configService: ConfigService,
    private readonly authService: AuthService,
    private readonly urlConfigService: UrlConfigService,
  ) {
    const clientId = configService.get<string>('GOOGLE_CLIENT_ID');
    const clientSecret = configService.get<string>('GOOGLE_CLIENT_SECRET');
    const callbackURL = urlConfigService.getOAuthCallbackUrl('google');

    // Validate required configuration
    if (!clientId || !clientSecret) {
      const missingVars: string[] = [];
      if (!clientId) missingVars.push('GOOGLE_CLIENT_ID');
      if (!clientSecret) missingVars.push('GOOGLE_CLIENT_SECRET');

      throw new Error(
        `Missing required Google OAuth configuration: ${missingVars.join(', ')}. ` +
          'Please check your .env file and ensure these variables are set.',
      );
    }

    super({
      clientID: clientId,
      clientSecret: clientSecret,
      callbackURL,
      scope: ['email', 'profile', 'openid'],
      accessType: 'offline', // Request refresh token
      prompt: 'consent', // Force consent screen to ensure we get a refresh token
      passReqToCallback: false, // Changed to false for simpler validation
    });

    this.logger.log('Google OAuth strategy initialized successfully');
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
        provider: 'google',
        providerId: profile.id,
        accessToken,
        refreshToken,
        providerData: {
          profile,
          raw: profile._raw,
        },
      };

      this.logger.log(`Google OAuth validation for user: ${user.email}`);
      return this.authService.validateOAuthUser(user);
    } catch (error) {
      this.logger.error('Google OAuth validation failed:', error.message);
      throw error;
    }
  }
}
