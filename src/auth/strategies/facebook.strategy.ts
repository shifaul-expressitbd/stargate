// src/auth/strategies/facebook.strategy.ts
import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PassportStrategy } from '@nestjs/passport';
import { Profile, Strategy } from 'passport-facebook';
import { UrlConfigService } from '../../config/url.config';
import { OAuthService } from '../services/oauth.service';

@Injectable()
export class FacebookStrategy extends PassportStrategy(Strategy, 'facebook') {
  private readonly logger = new Logger(FacebookStrategy.name);

  constructor(
    private readonly configService: ConfigService,
    private readonly oauthService: OAuthService,
    private readonly urlConfigService: UrlConfigService,
  ) {
    const appId = configService.get<string>('FACEBOOK_APP_ID');
    const appSecret = configService.get<string>('FACEBOOK_APP_SECRET');
    const callbackURL = urlConfigService.getOAuthCallbackUrl('facebook');

    // Validate required configuration
    if (!appId || !appSecret) {
      const missingVars: string[] = [];
      if (!appId) missingVars.push('FACEBOOK_APP_ID');
      if (!appSecret) missingVars.push('FACEBOOK_APP_SECRET');

      throw new Error(
        `Missing required Facebook OAuth configuration: ${missingVars.join(', ')}. ` +
          'Please check your .env file and ensure these variables are set.',
      );
    }

    super({
      clientID: appId,
      clientSecret: appSecret,
      callbackURL,
      scope: ['email', 'public_profile'],
      profileFields: ['id', 'emails', 'name', 'photos'],
    });

    this.logger.log('Facebook OAuth strategy initialized successfully');
  }

  async validate(
    accessToken: string,
    refreshToken: string,
    profile: Profile,
  ): Promise<any> {
    try {
      const { emails, name, photos } = profile;

      if (!emails || emails.length === 0) {
        throw new Error('No email found in Facebook profile');
      }

      const user = {
        email: emails[0].value,
        name:
          `${name?.givenName || ''} ${name?.familyName || ''}`.trim() ||
          'Facebook User',
        avatar: photos?.[0]?.value || null,
        provider: 'facebook',
        providerId: profile.id,
        accessToken,
        refreshToken,
        providerData: {
          profile,
          raw: profile._raw,
        },
      };

      this.logger.log(`Facebook OAuth validation for user: ${user.email}`);
      return this.oauthService.validateOAuthUser(user);
    } catch (error) {
      this.logger.error('Facebook OAuth validation failed:', error.message);
      throw error;
    }
  }
}
