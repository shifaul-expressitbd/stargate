import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PassportStrategy } from '@nestjs/passport';
import { Profile, Strategy } from 'passport-github2';
import { UrlConfigService } from '../../config/url.config';
import { AuthCoreService } from '../services/auth-core.service';

@Injectable()
export class GithubStrategy extends PassportStrategy(Strategy, 'github') {
  private readonly logger = new Logger(GithubStrategy.name);

  constructor(
    private readonly configService: ConfigService,
    private readonly authCoreService: AuthCoreService,
    private readonly urlConfigService: UrlConfigService,
  ) {
    const clientId = configService.get<string>('GITHUB_CLIENT_ID');
    const clientSecret = configService.get<string>('GITHUB_CLIENT_SECRET');
    const callbackURL = urlConfigService.getOAuthCallbackUrl('github');

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

      let email: string | null = null;

      // First, try to get email from profile.emails
      if (emails && emails.length > 0) {
        email = emails[0].value;
      }

      // If no email in profile, fetch from GitHub API
      if (!email) {
        try {
          email = await this.fetchPrimaryEmail(accessToken);
        } catch (apiError) {
          this.logger.warn(
            'Failed to fetch email from GitHub API:',
            apiError.message,
          );
        }
      }

      // If still no email, we can't proceed
      if (!email) {
        throw new Error(
          'No email found in GitHub profile. Please make sure your GitHub email is public or verified, or grant email access to the OAuth app.',
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
      return this.authCoreService.validateOAuthUser(user);
    } catch (error) {
      this.logger.error('GitHub OAuth validation failed:', error.message);
      throw error;
    }
  }

  /**
   * Fetch user's primary email from GitHub API when not available in profile
   */
  private async fetchPrimaryEmail(accessToken: string): Promise<string | null> {
    try {
      const response = await fetch('https://api.github.com/user/emails', {
        headers: {
          Authorization: `Bearer ${accessToken}`,
          'User-Agent': 'StarGate-Platform',
          Accept: 'application/vnd.github.v3+json',
        },
      });

      if (!response.ok) {
        throw new Error(
          `GitHub API error: ${response.status} ${response.statusText}`,
        );
      }

      const emails = await response.json();

      if (!Array.isArray(emails) || emails.length === 0) {
        return null;
      }

      // Find primary and verified email
      const primaryEmail = emails.find(
        (email) => email.primary && email.verified,
      );
      if (primaryEmail) {
        return primaryEmail.email;
      }

      // Fallback to any verified email
      const verifiedEmail = emails.find((email) => email.verified);
      if (verifiedEmail) {
        return verifiedEmail.email;
      }

      // Last resort: any email
      return emails[0]?.email || null;
    } catch (error) {
      this.logger.error('Error fetching email from GitHub API:', error.message);
      throw error;
    }
  }
}
