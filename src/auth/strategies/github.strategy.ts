import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PassportStrategy } from '@nestjs/passport';
import { Profile, Strategy } from 'passport-github2';
import { AuthService } from '../auth.service';

@Injectable()
export class GithubStrategy extends PassportStrategy(Strategy, 'github') {
  private readonly logger = new Logger(GithubStrategy.name);

  constructor(
    private readonly configService: ConfigService,
    private readonly authService: AuthService,
  ) {
    const clientId = configService.get<string>('GITHUB_CLIENT_ID');
    const clientSecret = configService.get<string>('GITHUB_CLIENT_SECRET');

    // Build callback URL with proper prefix
    const baseUrl =
      process.env.NODE_ENV === 'production'
        ? 'https://your-domain.com'
        : 'http://localhost:5555';
    const callbackURL = `${baseUrl}/api/auth/github/callback`;

    // Log configuration values (without sensitive data) for debugging
    console.log('GitHub OAuth Config:', {
      clientId: clientId ? `${clientId.substring(0, 10)}...` : 'NOT SET',
      clientSecret: clientSecret ? 'SET' : 'NOT SET',
      callbackURL,
    });

    // Validate required configuration
    if (!clientId || !clientSecret) {
      const missingVars: string[] = [];
      if (!clientId) missingVars.push('GITHUB_CLIENT_ID');
      if (!clientSecret) missingVars.push('GITHUB_CLIENT_SECRET');

      throw new Error(
        `Missing required GitHub OAuth configuration: ${missingVars.join(', ')}. ` +
          'Please check your .env file and ensure these variables are set.',
      );
    }

    super({
      clientID: clientId,
      clientSecret: clientSecret,
      callbackURL,
      scope: ['user:email'],
    });

    this.logger.log('GitHub OAuth strategy initialized successfully');
  }

  async validate(
    accessToken: string,
    refreshToken: string,
    profile: Profile,
  ): Promise<any> {
    try {
      const { emails, username, displayName, photos } = profile;

      // GitHub might not always provide email in profile.emails
      // We need to handle this case
      let email = null;
      if (emails && emails.length > 0) {
        email = emails[0].value;
      }

      // If no email is available, we can't proceed as email is required
      if (!email) {
        throw new Error(
          'No email found in GitHub profile. Please make sure your GitHub email is public or verified.',
        );
      }

      const user = {
        email,
        name: displayName || username || 'GitHub User',
        avatar: photos?.[0]?.value || null,
        provider: 'github',
        providerId: profile.id,
        accessToken,
        refreshToken,
        providerData: {
          profile,
          username,
          raw: profile._raw,
        },
      };

      this.logger.log(`GitHub OAuth validation for user: ${user.email}`);
      return this.authService.validateOAuthUser(user);
    } catch (error) {
      this.logger.error('GitHub OAuth validation failed:', error.message);
      throw error;
    }
  }
}
