import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class UrlConfigService {
  constructor(private readonly configService: ConfigService) {}

  /**
   * Get the backend URL from environment variable
   */
  getBackendUrl(): string {
    return this.configService.get<string>(
      'BACKEND_URL',
      'http://localhost:5555',
    );
  }

  /**
   * Get frontend URL
   */
  getFrontendUrl(): string {
    return this.configService.get<string>(
      'FRONTEND_URL',
      'http://localhost:4173',
    );
  }

  /**
   * Get base URL (alias for getBackendUrl for backward compatibility)
   */
  getBaseUrl(): string {
    return this.getBackendUrl();
  }

  /**
   * Get API URL (for internal API calls)
   */
  getApiUrl(): string {
    return this.getBackendUrl();
  }

  /**
   * Get CORS origins from environment variable
   */
  getCorsOrigins(): string[] {
    const corsEnv = this.configService.get<string>('CORS_ORIGIN');

    if (corsEnv) {
      return corsEnv.split(',').map((origin) => origin.trim());
    }

    // Default origins
    return [
      this.getFrontendUrl(),
      this.getBackendUrl(),
      'https://accounts.google.com', // Google OAuth
    ];
  }

  /**
   * Generate OAuth callback URL for a provider
   */
  getOAuthCallbackUrl(provider: string): string {
    const backendUrl = this.getBackendUrl();
    return `${backendUrl}/api/auth/${provider}/callback`;
  }

  /**
   * Generate OAuth authorization URL
   */
  getOAuthAuthUrl(provider: string): string {
    const backendUrl = this.getBackendUrl();
    return `${backendUrl}/api/auth/${provider}`;
  }

  /**
   * Generate Swagger URL
   */
  getSwaggerUrl(): string {
    const backendUrl = this.getBackendUrl();
    return `${backendUrl}/api/docs`;
  }

  /**
   * Generate password reset URL
   */
  getPasswordResetUrl(token: string): string {
    const frontendUrl = this.getFrontendUrl();
    return `${frontendUrl}/reset-password?token=${token}`;
  }

  /**
   * Generate email verification URL
   */
  getEmailVerificationUrl(token: string): string {
    const frontendUrl = this.getFrontendUrl();
    return `${frontendUrl}/verify-email?token=${token}`;
  }

  /**
   * Generate auth redirect URL
   */
  getAuthRedirectUrl(
    success: boolean,
    params: Record<string, any> = {},
  ): string {
    const frontendUrl = this.getFrontendUrl();
    const basePath = `${frontendUrl}/auth/callback`;

    const searchParams = new URLSearchParams();
    searchParams.append('success', success.toString());

    Object.entries(params).forEach(([key, value]) => {
      searchParams.append(key, String(value));
    });

    return `${basePath}?${searchParams.toString()}`;
  }
}
