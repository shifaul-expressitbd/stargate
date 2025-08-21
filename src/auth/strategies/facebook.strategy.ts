// src/auth/strategies/facebook.strategy.ts
import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PassportStrategy } from '@nestjs/passport';
import { Profile, Strategy } from 'passport-facebook';
import { AuthService } from '../auth.service';

@Injectable()
export class FacebookStrategy extends PassportStrategy(Strategy, 'facebook') {
  private readonly logger = new Logger(FacebookStrategy.name);

  constructor(
    private readonly configService: ConfigService,
    private readonly authService: AuthService,
  ) {
    const appId = configService.get<string>('FACEBOOK_APP_ID');
    const appSecret = configService.get<string>('FACEBOOK_APP_SECRET');

    // Build callback URL
    const baseUrl =
      process.env.NODE_ENV === 'production'
        ? 'https://your-domain.com'
        : 'http://localhost:5555';
    const callbackURL = `${baseUrl}/api/auth/facebook/callback`;

    console.log('Facebook OAuth Config:', {
      appId: appId ? `${appId.substring(0, 5)}...` : 'NOT SET',
      appSecret: appSecret ? 'SET' : 'NOT SET',
      callbackURL,
    });

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
    done: (error: any, user?: any) => void,
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
        accessToken,
        refreshToken,
        facebookId: profile.id,
      };

      this.logger.log(`Facebook OAuth validation for user: ${user.email}`);

      const validatedUser = await this.authService.validateOAuthUser(user);
      done(null, validatedUser);
    } catch (error) {
      this.logger.error('Facebook OAuth validation failed:', error.message);
      done(error, null);
    }
  }
}
