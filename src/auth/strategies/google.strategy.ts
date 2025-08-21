// src/auth/strategies/google.strategy.ts
import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PassportStrategy } from '@nestjs/passport';
import { Profile, Strategy } from 'passport-google-oauth20';
import { AuthService } from '../auth.service';

@Injectable()
export class GoogleStrategy extends PassportStrategy(Strategy, 'google') {
  private readonly logger = new Logger(GoogleStrategy.name);

  constructor(
    private readonly configService: ConfigService,
    private readonly authService: AuthService,
  ) {
    const clientId = configService.get<string>('GOOGLE_CLIENT_ID');
    const clientSecret = configService.get<string>('GOOGLE_CLIENT_SECRET');

    // Build callback URL with proper prefix
    const baseUrl =
      process.env.NODE_ENV === 'production'
        ? 'https://your-domain.com'
        : 'http://localhost:5555';
    const callbackURL = `${baseUrl}/api/auth/google/callback`;

    // Log configuration values (without sensitive data) for debugging
    console.log('Google OAuth Config:', {
      clientId: clientId ? `${clientId.substring(0, 10)}...` : 'NOT SET',
      clientSecret: clientSecret ? 'SET' : 'NOT SET',
      callbackURL,
    });

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
      scope: ['email', 'profile'],
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
        accessToken,
        refreshToken,
        googleId: profile.id,
      };

      this.logger.log(`Google OAuth validation for user: ${user.email}`);
      return this.authService.validateOAuthUser(user);
    } catch (error) {
      this.logger.error('Google OAuth validation failed:', error.message);
      throw error;
    }
  }
}
